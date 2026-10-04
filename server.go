//go:build !js

package mosh

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unixshells/vt-go"
	"github.com/creack/pty"
)

const (
	// Server gives up waiting for client after this.
	associationTimeout = 60 * time.Second

	// Network timeout for idle sessions.
	defaultNetworkTimeout = 24 * time.Hour

	// Default terminal size.
	defaultCols = 80
	defaultRows = 24
)

// Server is a native mosh server. It listens on UDP, runs a shell in a PTY,
// bridges data through the SSP transport, and diffs terminal framebuffers
// to produce HostMessage updates for the client.
type Server struct {
	key  []byte
	ocb  *OCB
	port int
	conn *net.UDPConn
	ptmx *os.File
	cmd  *exec.Cmd

	shell string
	cols  int
	rows  int

	// Transport handles SSP sequencing, fragmentation, and crypto.
	transport *Transport

	// VT emulator and framebuffer state for CUP-based diffing.
	emu        *vt.Emulator
	baseFB     *Framebuffer // what client has (last-acked)
	sentFB     *Framebuffer // what we last sent (pending ack)
	curVisible atomic.Bool

	// Remote client address — set on first received datagram.
	mu         sync.Mutex
	clientAddr *net.UDPAddr

	started  chan struct{} // closed when PTY is running
	done     chan struct{}
	doneOnce sync.Once
}

// GenerateKey creates a random 128-bit mosh key and returns it as base64.
func GenerateKey() ([]byte, string, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	return key, base64.StdEncoding.EncodeToString(key), nil
}

// NewServer creates a native mosh server.
// It binds a UDP port, generates a key, and is ready to serve.
func NewServer(shell string, portLow, portHigh int) (*Server, error) {
	key, _, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	ocb, err := NewOCB(key)
	if err != nil {
		return nil, err
	}

	if shell == "" {
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
	}

	conn, port, err := BindUDP(portLow, portHigh)
	if err != nil {
		return nil, err
	}

	return &Server{
		key:       key,
		ocb:       ocb,
		port:      port,
		conn:      conn,
		shell:     shell,
		cols:      defaultCols,
		rows:      defaultRows,
		transport: NewTransport(ocb, true),
		started:   make(chan struct{}),
		done:      make(chan struct{}),
	}, nil
}

// Port returns the UDP port the server is listening on.
func (s *Server) Port() int {
	return s.port
}

// KeyBase64 returns the mosh key as a base64 string (22 chars, no padding).
func (s *Server) KeyBase64() string {
	encoded := base64.StdEncoding.EncodeToString(s.key)
	for len(encoded) > 0 && encoded[len(encoded)-1] == '=' {
		encoded = encoded[:len(encoded)-1]
	}
	return encoded
}

// ConnectLine returns the MOSH CONNECT line that clients parse.
func (s *Server) ConnectLine() string {
	return fmt.Sprintf("MOSH CONNECT %d %s", s.port, s.KeyBase64())
}

// Serve starts the shell and event loop. Blocks until the session ends.
func (s *Server) Serve() error {
	s.cmd = exec.Command(s.shell)
	s.cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"MOSH_SERVER_NETWORK_TMOUT=86400",
	)

	var err error
	s.ptmx, err = pty.Start(s.cmd)
	if err != nil {
		s.conn.Close()
		return fmt.Errorf("pty: %w", err)
	}
	close(s.started)

	pty.Setsize(s.ptmx, &pty.Winsize{
		Rows: uint16(s.rows),
		Cols: uint16(s.cols),
	})

	s.emu = vt.NewEmulator(s.cols, s.rows)
	s.curVisible.Store(true)
	s.emu.SetCallbacks(vt.Callbacks{
		CursorVisibility: func(visible bool) { s.curVisible.Store(visible) },
	})
	s.baseFB = NewFramebuffer(s.cols, s.rows)

	var wg sync.WaitGroup
	wg.Add(3)

	// PTY reader: reads shell output into pending buffer.
	ptyOutput := make(chan []byte, 64)
	go func() {
		defer wg.Done()
		s.readPTY(ptyOutput)
	}()

	// UDP receiver: decrypts datagrams, feeds to transport.
	userInput := make(chan UserInstruction, 64)
	go func() {
		defer wg.Done()
		s.recvUDP(userInput)
	}()

	// Main loop: process input, diff framebuffer, send via transport.
	go func() {
		defer wg.Done()
		s.mainLoop(ptyOutput, userInput)
	}()

	err = s.cmd.Wait()
	s.stop()
	s.ptmx.Close()
	s.conn.Close()
	wg.Wait()
	return err
}

// stop closes done once; Close and the serve loops may all try.
func (s *Server) stop() {
	s.doneOnce.Do(func() { close(s.done) })
}

// Done returns a channel that is closed when the server shuts down.
func (s *Server) Done() <-chan struct{} {
	return s.done
}

// ServeRW runs the event loop using an external io.ReadWriteCloser instead
// of spawning a shell in a PTY. The caller provides terminal I/O through rw
// and a resize callback. When rw is closed or reaches EOF, the server shuts down.
func (s *Server) ServeRW(rw io.ReadWriteCloser, resize func(cols, rows uint16)) error {
	close(s.started)

	s.emu = vt.NewEmulator(s.cols, s.rows)
	s.curVisible.Store(true)
	s.emu.SetCallbacks(vt.Callbacks{
		CursorVisibility: func(visible bool) { s.curVisible.Store(visible) },
	})
	s.baseFB = NewFramebuffer(s.cols, s.rows)

	var wg sync.WaitGroup
	wg.Add(3)

	ioOutput := make(chan []byte, 64)
	go func() {
		defer wg.Done()
		s.readIO(rw, ioOutput)
	}()

	userInput := make(chan UserInstruction, 64)
	go func() {
		defer wg.Done()
		s.recvUDP(userInput)
	}()

	go func() {
		defer wg.Done()
		s.mainLoopRW(rw, resize, ioOutput, userInput)
	}()

	<-s.done
	rw.Close()
	s.conn.Close()
	wg.Wait()
	return nil
}

func (s *Server) readIO(r io.Reader, out chan<- []byte) {
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case out <- data:
			case <-s.done:
				return
			}
		}
		if err != nil {
			s.stop()
			return
		}
	}
}

func (s *Server) mainLoopRW(rw io.Writer, resize func(cols, rows uint16), ioOutput <-chan []byte, userInput <-chan UserInstruction) {
	// Wait for the first client datagram. If no client connects within
	// 60 seconds, this was a failed setup — shut down to release resources.
	deadline := time.After(associationTimeout)
	for {
		s.mu.Lock()
		addr := s.clientAddr
		s.mu.Unlock()
		if addr != nil {
			break
		}
		select {
		case <-s.done:
			return
		case <-deadline:
			s.stop()
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	dirty := false

	for {
		select {
		case <-s.done:
			return

		case data, ok := <-ioOutput:
			if !ok {
				return
			}
			s.emu.Write(data)
			dirty = true

		case ui := <-userInput:
			if len(ui.Keys) > 0 {
				rw.Write(ui.Keys)
			}
			if ui.Width > 0 && ui.Height > 0 {
				s.mu.Lock()
				s.cols = int(ui.Width)
				s.rows = int(ui.Height)
				s.mu.Unlock()
				if resize != nil {
					resize(uint16(ui.Width), uint16(ui.Height))
				}
				s.emu.Resize(int(ui.Width), int(ui.Height))
				s.baseFB = NewFramebuffer(int(ui.Width), int(ui.Height))
				s.sentFB = nil
				dirty = true
			}

		case <-ticker.C:
			if s.sentFB != nil && s.transport.AckedByRemote() >= s.transport.SentNum() {
				s.baseFB = s.sentFB
				s.sentFB = nil
			}

			if dirty {
				currentFB := SnapshotEmulator(s.emu, s.curVisible.Load())
				diffBytes := currentFB.Diff(s.baseFB)
				if len(diffBytes) > 0 {
					hi := HostInstruction{Hoststring: diffBytes, EchoAckNum: -1}
					s.transport.SetPending(marshalHostMessage([]HostInstruction{hi}))
					s.sentFB = currentFB
				}
				dirty = false
			}

			datagrams := s.transport.Tick()
			s.sendDatagrams(datagrams)
		}
	}
}

// Close shuts down the server.
func (s *Server) Close() {
	// If Serve() was never called, just close the socket.
	select {
	case <-s.done:
		return
	case <-s.started:
		// PTY is running — kill it.
	default:
		// Serve() never called. Close socket and unblock any future Serve().
		s.conn.Close()
		return
	}

	if s.cmd == nil {
		// ServeRW: no process to kill. End the session; ServeRW closes rw.
		s.stop()
		return
	}
	if s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
	s.conn.Close()
	if s.ptmx != nil {
		s.ptmx.Close()
	}
}

// mainLoop is the SSP event loop. It feeds PTY output to a VT emulator,
// snapshots the framebuffer, diffs against the last-acked state, and
// sends CUP-based updates via the transport.
func (s *Server) mainLoop(ptyOutput <-chan []byte, userInput <-chan UserInstruction) {
	// Wait for the first client datagram. If no client connects within
	// 60 seconds, this was a failed setup — shut down to release resources.
	deadline := time.After(associationTimeout)
	for {
		s.mu.Lock()
		addr := s.clientAddr
		s.mu.Unlock()
		if addr != nil {
			break
		}
		select {
		case <-s.done:
			return
		case <-deadline:
			s.stop()
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	dirty := false

	for {
		select {
		case <-s.done:
			return

		case data, ok := <-ptyOutput:
			if !ok {
				return
			}
			s.emu.Write(data)
			dirty = true

		case ui := <-userInput:
			if len(ui.Keys) > 0 {
				s.ptmx.Write(ui.Keys)
			}
			if ui.Width > 0 && ui.Height > 0 {
				s.mu.Lock()
				s.cols = int(ui.Width)
				s.rows = int(ui.Height)
				s.mu.Unlock()
				pty.Setsize(s.ptmx, &pty.Winsize{
					Cols: uint16(ui.Width),
					Rows: uint16(ui.Height),
				})
				s.emu.Resize(int(ui.Width), int(ui.Height))
				s.baseFB = NewFramebuffer(int(ui.Width), int(ui.Height))
				s.sentFB = nil
				dirty = true
			}

		case <-ticker.C:
			// Advance base when client acks all pending.
			if s.sentFB != nil && s.transport.AckedByRemote() >= s.transport.SentNum() {
				s.baseFB = s.sentFB
				s.sentFB = nil
			}

			if dirty {
				currentFB := SnapshotEmulator(s.emu, s.curVisible.Load())
				diffBytes := currentFB.Diff(s.baseFB)
				if len(diffBytes) > 0 {
					hi := HostInstruction{Hoststring: diffBytes, EchoAckNum: -1}
					s.transport.SetPending(marshalHostMessage([]HostInstruction{hi}))
					s.sentFB = currentFB
				}
				dirty = false
			}

			datagrams := s.transport.Tick()
			s.sendDatagrams(datagrams)
		}
	}
}

// readPTY reads from the PTY and sends data to the channel.
func (s *Server) readPTY(out chan<- []byte) {
	buf := make([]byte, 8192)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.ptmx.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case out <- data:
			case <-s.done:
				return
			}
		}
		if err != nil && !os.IsTimeout(err) {
			return
		}
	}
}

// recvUDP reads encrypted datagrams, decrypts via transport, parses UserMessage.
func (s *Server) recvUDP(out chan<- UserInstruction) {
	buf := make([]byte, maxPayload+64)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if os.IsTimeout(err) {
				if time.Since(s.transport.LastRecv()) > defaultNetworkTimeout {
					return
				}
				continue
			}
			return
		}
		if n < minDatagram {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		// Feed to transport — only update clientAddr on successful decrypt.
		diff := s.transport.Recv(data)

		s.mu.Lock()
		s.clientAddr = addr
		s.mu.Unlock()

		if diff == nil {
			continue
		}

		// Parse UserMessage protobuf.
		instrs, err := unmarshalUserMessage(diff)
		if err != nil {
			continue
		}
		for _, ui := range instrs {
			select {
			case out <- ui:
			case <-s.done:
				return
			}
		}
	}
}

// sendDatagrams sends wire datagrams to the client.
func (s *Server) sendDatagrams(datagrams [][]byte) {
	s.mu.Lock()
	addr := s.clientAddr
	s.mu.Unlock()
	if addr == nil {
		return
	}
	for _, dg := range datagrams {
		s.conn.WriteToUDP(dg, addr)
	}
}

// BindUDP binds a UDP socket on the first available port in [low, high].
func BindUDP(low, high int) (*net.UDPConn, int, error) {
	if low == 0 && high == 0 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return nil, 0, err
		}
		return conn, conn.LocalAddr().(*net.UDPAddr).Port, nil
	}

	if high < low {
		high = low
	}

	for port := low; port <= high; port++ {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: port,
		})
		if err != nil {
			continue
		}
		return conn, port, nil
	}
	return nil, 0, fmt.Errorf("no available UDP port in range %d-%d", low, high)
}

// WriteTo implements io.WriterTo for streaming output to an SSH channel.
func (s *Server) WriteTo(w io.Writer) (int64, error) {
	line := s.ConnectLine() + "\n"
	n, err := w.Write([]byte(line))
	return int64(n), err
}

// sendToClient encrypts and sends a raw payload datagram to the client.
// Used by legacy tests that don't go through the Transport.
func (s *Server) sendToClient(payload []byte) {
	s.mu.Lock()
	addr := s.clientAddr
	if addr == nil {
		s.mu.Unlock()
		return
	}

	s.transport.mu.Lock()
	s.transport.seqOut++
	seq := s.transport.seqOut
	lastTS := s.transport.lastTS
	s.transport.mu.Unlock()
	s.mu.Unlock()

	dirSeq := dirToClient | (seq & seqMask)
	var dirSeqBytes [8]byte
	binary.BigEndian.PutUint64(dirSeqBytes[:], dirSeq)

	var nonce [12]byte
	copy(nonce[4:], dirSeqBytes[:])

	ts := uint16(time.Now().UnixMilli() & 0xffff)
	plaintext := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(plaintext[0:], ts)
	binary.BigEndian.PutUint16(plaintext[2:], lastTS)
	if len(payload) > 0 {
		copy(plaintext[4:], payload)
	}

	tagAndCT := s.ocb.Encrypt(nonce[:], plaintext)

	wire := make([]byte, 8+len(tagAndCT))
	copy(wire[:8], dirSeqBytes[:])
	copy(wire[8:], tagAndCT)

	s.conn.WriteToUDP(wire, addr)
}

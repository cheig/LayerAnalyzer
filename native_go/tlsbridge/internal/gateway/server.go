package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

const (
	DefaultConnections    = engine.DefaultConnectionBudget
	MaxConnections        = engine.MaxConnectionBudget
	DefaultAuthentication = 64
	MaxAuthentication     = 128
	AuthenticationTimeout = time.Second
	ConnectTimeout        = 10 * time.Second
)

// DialFunc must honor cancellation/deadlines and return only a connected TCP
// socket after synchronous protect/bind. There is deliberately no default.
// If it returns a socket alongside a failure, gateway still closes that socket.
type DialFunc func(context.Context, Metadata) (net.Conn, engine.Code)

// FlowHandler runs after READY has been flushed. It must finish on cancellation
// or socket closure, must not retain connections after returning, and must not
// call Server.Close itself (Close joins this handler). Gateway owns both sockets.
type FlowHandler func(context.Context, Metadata, net.Conn, net.Conn)

type Options struct {
	CaptureID         string
	NetworkGeneration int64
	Dial              DialFunc
	Handle            FlowHandler
	// Zero selects 64. Production derives this candidate subset ceiling from
	// the same frozen TCP limit as Kotlin, with no additive capacity.
	Capacity               int
	AuthenticationCapacity int
	// Shared candidate accountant; standalone gateways construct a bounded budget.
	Budget *engine.Budget
}

type Server struct {
	listener       net.Listener
	port           uint16
	ctx            context.Context
	cancel         context.CancelFunc
	options        Options
	token          [32]byte
	slots          chan struct{}
	mu             sync.Mutex
	connections    map[net.Conn]bool
	authentication int
	metrics        Stats
	workers        sync.WaitGroup
	done           chan struct{}
}

// Start creates a fresh token and listens only on IPv4 loopback's random port.
// It is a component factory, not evidence that the TLS engine is assembled.
func Start(parent context.Context, options Options) (*Server, engine.Code) {
	if parent == nil || !engine.ValidID(options.CaptureID) || options.NetworkGeneration < 0 ||
		options.Dial == nil || options.Handle == nil || options.Capacity < 0 || options.Capacity > MaxConnections || options.AuthenticationCapacity < 0 || options.AuthenticationCapacity > MaxAuthentication {
		return nil, engine.InvalidArgument
	}
	if parent.Err() != nil {
		return nil, engine.Cancelled
	}
	if options.Capacity == 0 {
		options.Capacity = DefaultConnections
	}
	if options.AuthenticationCapacity == 0 {
		options.AuthenticationCapacity = DefaultAuthentication
	}
	if options.Budget == nil {
		var code engine.Code
		options.Budget, code = engine.NewBudget(engine.Limits{Connections: options.Capacity})
		if code != engine.OK {
			return nil, code
		}
	}
	if options.Budget.ConnectionCapacity() != options.Capacity {
		return nil, engine.InvalidArgument
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{ctx: ctx, cancel: cancel, options: options,
		slots: make(chan struct{}, options.Capacity), connections: make(map[net.Conn]bool), done: make(chan struct{})}
	if _, err := rand.Read(s.token[:]); err != nil {
		cancel()
		return nil, engine.IOError
	}
	listener, err := new(net.ListenConfig).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		clear(s.token[:])
		cancel()
		return nil, engine.IOError
	}
	s.listener = listener
	s.port = uint16(listener.Addr().(*net.TCPAddr).Port)
	go s.run()
	return s, engine.OK
}

func (s *Server) Port() uint16 { return s.port }

// Token returns an independent base64url buffer for C05's dedicated memory
// output. Callers must clear it when done; never put it in ordinary JSON/logs.
// After shutdown no token is available.
func (s *Server) Token() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return nil
	}
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(s.token)))
	base64.RawURLEncoding.Encode(out, s.token[:])
	return out
}

// Close is idempotent and joins every worker. The engine's existing bounded
// stop API can time out while this waits for an injected callback to drain.
func (s *Server) Close() {
	s.cancel()
	<-s.done
}

func (s *Server) run() {
	// Cancellation closes active sockets to unblock reads/writes as well as
	// Accept. Connection registration is checked under the same lock.
	shutdown := make(chan struct{})
	go func() {
		<-s.ctx.Done()
		_ = s.listener.Close()
		s.mu.Lock()
		for connection := range s.connections {
			_ = connection.Close()
		}
		s.mu.Unlock()
		close(shutdown)
	}()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			break
		}
		s.mu.Lock()
		if s.ctx.Err() != nil || s.authentication >= s.options.AuthenticationCapacity ||
			len(s.connections) >= s.options.Capacity+s.options.AuthenticationCapacity {
			s.metrics.RejectedBeforeAuthentication++
			s.mu.Unlock()
			// No goroutine, header allocation or external dial for an admission
			// flood. Immediate close is permitted before authentication.
			_ = connection.Close()
			continue
		}
		s.connections[connection] = false
		s.authentication++
		s.metrics.Accepted++
		if s.authentication > s.metrics.PeakAuthentication {
			s.metrics.PeakAuthentication = s.authentication
		}
		if len(s.connections) > s.metrics.PeakAccepted {
			s.metrics.PeakAccepted = len(s.connections)
		}
		s.workers.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.workers.Done()
			defer func() {
				_ = connection.Close()
				s.mu.Lock()
				if active, exists := s.connections[connection]; exists && !active {
					s.authentication--
				}
				delete(s.connections, connection)
				s.mu.Unlock()
			}()
			s.serve(connection)
		}()
	}
	s.cancel()
	<-shutdown
	s.workers.Wait()
	s.mu.Lock()
	clear(s.token[:])
	s.mu.Unlock()
	close(s.done)
}

func (s *Server) serve(down net.Conn) {
	if down.SetReadDeadline(time.Now().Add(AuthenticationTimeout)) != nil {
		return
	}
	reader := bufio.NewReaderSize(down, MaxHeaderBytes)
	writer := bufio.NewWriterSize(down, MaxReplyBytes)
	reply := func(code engine.Code) bool {
		if s.ctx.Err() != nil {
			return false
		}
		if down.SetWriteDeadline(time.Now().Add(AuthenticationTimeout)) != nil {
			return false
		}
		return writeReply(writer, code) == nil
	}
	metadata, provided, code := readRequest(reader)
	defer clear(provided[:])
	if code != engine.OK {
		s.recordAuthenticationFailure()
		reply(code)
		return
	}
	// token is immutable until all workers have joined; no lock across dial.
	if subtle.ConstantTimeCompare(provided[:], s.token[:]) != 1 {
		s.recordAuthenticationFailure()
		reply(engine.InvalidArgument)
		return
	}
	if metadata.CaptureID != s.options.CaptureID {
		s.recordAuthenticationFailure()
		reply(engine.CaptureContextMissing)
		return
	}
	if metadata.NetworkGeneration != s.options.NetworkGeneration {
		s.recordAuthenticationFailure()
		reply(engine.StaleGeneration)
		return
	}
	// Reserve active while holding auth, then transfer atomically. Active includes dialing.
	s.mu.Lock()
	select {
	case s.slots <- struct{}{}:
	default:
		s.metrics.RejectedActiveCapacity++
		s.mu.Unlock()
		reply(engine.CapacityExceeded)
		return
	}
	var lease *engine.Lease
	if s.options.Budget != nil {
		var code engine.Code
		lease, code = s.options.Budget.Acquire(engine.ConnectionSlot)
		if code != engine.OK {
			<-s.slots
			s.metrics.RejectedActiveCapacity++
			s.mu.Unlock()
			reply(code)
			return
		}
	}
	if _, exists := s.connections[down]; exists {
		s.connections[down] = true
		s.authentication--
	}
	s.metrics.Authenticated++
	if len(s.slots) > s.metrics.PeakActive {
		s.metrics.PeakActive = len(s.slots)
	}
	s.mu.Unlock()
	defer func() { lease.Release(); s.mu.Lock(); <-s.slots; s.mu.Unlock() }()
	metadata.ConnectionLease = lease
	if s.ctx.Err() != nil {
		return
	}
	if down.SetReadDeadline(time.Time{}) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, ConnectTimeout)
	s.mu.Lock()
	s.metrics.DialAttempts++
	s.mu.Unlock()
	up, code := s.options.Dial(ctx, metadata)
	var closeOnce sync.Once
	closeUp := func() {
		if up != nil {
			closeOnce.Do(func() { _ = up.Close() })
		}
	}
	defer closeUp()
	// A misbehaving adapter may return a socket after its deadline. Never send
	// READY for an expired connection attempt, even when it returned OK.
	expired := ctx.Err() != nil
	cancel()
	if expired {
		s.recordDialFailure()
		reply(engine.Cancelled)
		return
	}
	if code != engine.OK {
		s.recordDialFailure()
		reply(code)
		return
	}
	if up == nil {
		s.recordDialFailure()
		reply(engine.IOError)
		return
	}
	// Shutdown must also unblock a handler waiting on the upstream socket.
	closeDone := make(chan struct{})
	stopClosing := context.AfterFunc(s.ctx, func() { closeUp(); close(closeDone) })
	defer func() {
		if !stopClosing() {
			<-closeDone
		}
	}()
	if up.SetDeadline(time.Time{}) != nil || !reply(engine.OK) {
		return
	}
	if down.SetDeadline(time.Time{}) != nil || s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	s.metrics.Ready++
	s.mu.Unlock()
	s.options.Handle(s.ctx, metadata, &bufferedConn{Conn: down, reader: reader}, up)
}

// Keep bytes prefetched while parsing metadata. Embedding only net.Conn loses
// TCP's half-close methods, so forward them for the later relay implementation.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *bufferedConn) CloseRead() error {
	if half, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return half.CloseRead()
	}
	return errors.ErrUnsupported
}

// Active includes dial and READY wait. SocketLimit covers listener, auth, both active
// sockets and one transient accept; TLS fallback replacements have a separate bound.
type Stats struct {
	AuthenticationFailures       uint64 `json:"authenticationFailures"`
	Authentication               int    `json:"authentication"`
	Active                       int    `json:"active"`
	AcceptedCurrent              int    `json:"acceptedCurrent"`
	AuthenticationLimit          int    `json:"authenticationLimit"`
	ActiveLimit                  int    `json:"activeLimit"`
	AcceptedLimit                int    `json:"acceptedLimit"`
	SocketLimit                  int    `json:"socketLimit"`
	PeakAuthentication           int    `json:"peakAuthentication"`
	PeakActive                   int    `json:"peakActive"`
	PeakAccepted                 int    `json:"peakAccepted"`
	Accepted                     uint64 `json:"accepted"`
	Authenticated                uint64 `json:"authenticated"`
	RejectedBeforeAuthentication uint64 `json:"rejectedBeforeAuthentication"`
	RejectedActiveCapacity       uint64 `json:"rejectedActiveCapacity"`
	DialAttempts                 uint64 `json:"dialAttempts"`
	DialFailures                 uint64 `json:"dialFailures"`
	Ready                        uint64 `json:"ready"`
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.metrics
	result.Authentication = s.authentication
	result.Active = len(s.slots)
	result.AcceptedCurrent = len(s.connections)
	result.AuthenticationLimit = s.options.AuthenticationCapacity
	result.ActiveLimit = s.options.Capacity
	result.AcceptedLimit = result.AuthenticationLimit + result.ActiveLimit
	result.SocketLimit = 2 + result.AuthenticationLimit + 2*result.ActiveLimit
	return result
}
func (s *Server) recordDialFailure() { s.mu.Lock(); s.metrics.DialFailures++; s.mu.Unlock() }

func (s *Server) recordAuthenticationFailure() {
	s.mu.Lock()
	s.metrics.AuthenticationFailures++
	s.mu.Unlock()
}

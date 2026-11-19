package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Explicit lifecycle-only doubles: these do not serve TCP/TLS or prove gateway
// readiness. The production manager never installs this factory.
type platformStub struct{}

func (platformStub) PrepareSocket(int, int64) Code                        { return OK }
func (platformStub) ResolveHost(string, int64) ([]byte, Code)             { return nil, Unsupported }
func (platformStub) VerifyUpstream([][]byte, string, string, string) Code { return Unsupported }
func (platformStub) OfferSecret(string, string, []byte) Code              { return SecretsIncomplete }
func fixture(t *testing.T) (Config, Material, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lifecycle test only"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	m, code := ParseMaterial(der, pkcs8, time.Now())
	if code != OK {
		t.Fatal(code)
	}
	g := int64(1)
	return Config{SchemaVersion: 1, CaptureID: "test-capture", NetworkGeneration: &g}, m, der, pkcs8
}
func sessionStub(close func()) *Session {
	return &Session{Port: 12345, Token: []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), Close: close}
}

func TestLifecycleRepeatedAndStaleHandles(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	var closes atomic.Int32
	m := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		return sessionStub(func() { closes.Add(1) }), OK
	})
	for i := 0; i < 100; i++ {
		h, port, token, c := m.Start(cfg, mat, platformStub{})
		if c != OK || h != uint64(i+1) || port == 0 || len(token) != 43 {
			t.Fatal(h, c)
		}
		if state, c := m.Snapshot(h); c != OK || state != Running {
			t.Fatal(state, c)
		}
		if h2, _, _, c := m.Start(cfg, mat, platformStub{}); c != NotReady || h2 != 0 {
			t.Fatal(h2, c)
		}
		if h > 1 {
			if c := m.Stop(h-1, time.Second); c != OK {
				t.Fatal(c)
			}
			if _, c := m.Snapshot(h); c != OK {
				t.Fatal(c)
			}
		}
		if c := m.Stop(h, time.Second); c != OK {
			t.Fatal(c)
		}
		if c := m.Stop(h, time.Second); c != OK {
			t.Fatal(c)
		}
		if _, c := m.Poll(h, 128); c != StaleGeneration {
			t.Fatal(c)
		}
	}
	if closes.Load() != 100 || m.active != nil {
		t.Fatal(closes.Load())
	}
}

func TestConcurrentStartSingleWinner(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	m := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		return sessionStub(func() {}), OK
	})
	var wg sync.WaitGroup
	var winners atomic.Int32
	var winner atomic.Uint64
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _, _, c := m.Start(cfg, mat, platformStub{})
			if c == OK {
				winners.Add(1)
				winner.Store(h)
			} else if c != NotReady {
				t.Errorf("code %v", c)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal(winners.Load())
	}
	if c := m.Stop(winner.Load(), time.Second); c != OK {
		t.Fatal(c)
	}
}

func TestStopDrainsCallbacksAndRejectsNewCalls(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	var callbacks *Callbacks
	m := NewManager(func(_ context.Context, _ Config, _ Material, c *Callbacks, _ *Runtime) (*Session, Code) {
		callbacks = c
		return sessionStub(func() {}), OK
	})
	h, _, _, _ := m.Start(cfg, mat, platformStub{})
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		callbacks.Call(func(Platform) Code { close(entered); <-release; return OK })
	}()
	<-entered
	if c := m.Stop(h, time.Millisecond); c != NotReady {
		t.Fatal(c)
	}
	if state, c := m.Snapshot(h); c != OK || state != Stopping {
		t.Fatal(state, c)
	}
	if c := callbacks.Call(func(Platform) Code { t.Error("callback after stop"); return OK }); c != Cancelled {
		t.Fatal(c)
	}
	if next, _, _, c := m.Start(cfg, mat, platformStub{}); c != NotReady || next != 0 {
		t.Fatal(next, c)
	}
	close(release)
	<-done
	if c := m.Stop(h, time.Second); c != OK {
		t.Fatal(c)
	}
	if c := callbacks.Call(func(Platform) Code { t.Error("callback after release"); return OK }); c != Cancelled {
		t.Fatal(c)
	}
}

func TestStopDeadlineAndPollRace(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	var closes atomic.Int32
	closing := make(chan struct{})
	m := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		return sessionStub(func() { closes.Add(1); <-closing }), OK
	})
	h, _, _, _ := m.Start(cfg, mat, platformStub{})
	if c := m.Stop(h, time.Millisecond); c != NotReady {
		t.Fatal(c)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, c := m.Poll(h, 128)
				if c != OK && c != StaleGeneration {
					t.Errorf("poll %v", c)
				}
			}
		}()
	}
	close(closing)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c := m.Stop(h, time.Second); c != OK {
				t.Errorf("stop %v", c)
			}
		}()
	}
	wg.Wait()
	if closes.Load() != 1 {
		t.Fatal(closes.Load())
	}
}

func TestUnassembledAndInvalidFactoryNeverReturnHandle(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	m := NewManager(nil)
	if m.Ready() {
		t.Fatal("unassembled engine ready")
	}
	if h, p, token, c := m.Start(cfg, mat, platformStub{}); c != NotReady || h != 0 || p != 0 || token != nil {
		t.Fatal(h, p, c)
	}
	var closes atomic.Int32
	m = NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		return &Session{Close: func() { closes.Add(1) }}, OK
	})
	if h, p, token, c := m.Start(cfg, mat, platformStub{}); c != NotReady || h != 0 || p != 0 || token != nil {
		t.Fatal(h, p, c)
	}
	if m.active != nil || closes.Load() != 1 {
		t.Fatal("startup rollback failed")
	}
}

func TestStartingRejectsGuessedStopAndDoubleStart(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	m := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		close(entered)
		<-release
		return sessionStub(func() {}), OK
	})
	done := make(chan uint64)
	go func() {
		h, _, _, c := m.Start(cfg, mat, platformStub{})
		if c != OK {
			t.Errorf("start %v", c)
		}
		done <- h
	}()
	<-entered
	if state, c := m.Snapshot(1); c != OK || state != Starting {
		t.Fatal(state, c)
	}
	if c := m.Stop(1, time.Millisecond); c != NotReady {
		t.Fatal(c)
	}
	if h, _, _, c := m.Start(cfg, mat, platformStub{}); c != NotReady || h != 0 {
		t.Fatal(h, c)
	}
	close(release)
	if c := m.Stop(<-done, time.Second); c != OK {
		t.Fatal(c)
	}
}

func TestHandleAndBudgetValidation(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	m := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		return sessionStub(func() {}), OK
	})
	if c := m.Stop(0, time.Second); c != InvalidArgument {
		t.Fatal(c)
	}
	if c := m.Stop(1, time.Second); c != StaleGeneration {
		t.Fatal(c)
	}
	if c := m.Stop(1, 6*time.Second); c != InvalidArgument {
		t.Fatal(c)
	}
	for _, max := range []uint32{0, 129, ^uint32(0)} {
		if _, c := m.Poll(1, max); c != InvalidArgument {
			t.Fatal(c)
		}
	}
	m.issued = 1<<63 - 1
	if h, _, _, c := m.Start(cfg, mat, platformStub{}); c != CapacityExceeded || h != 0 {
		t.Fatal(h, c)
	}
}

func TestConfigValidation(t *testing.T) {
	valid := `{"schemaVersion":1,"captureId":"capture_1","networkGeneration":0,"settings":{}}`
	if _, c := ParseConfig([]byte(valid)); c != OK {
		t.Fatal(c)
	}
	for _, data := range []string{"", "null", "[]", valid + "{}", `{"schemaVersion":2,"captureId":"capture","networkGeneration":0}`,
		`{"schemaVersion":1,"captureId":"../secret","networkGeneration":0}`, `{"schemaVersion":1,"captureId":"capture"}`,
		`{"schemaVersion":1,"captureId":"capture","networkGeneration":-1}`, `{"schemaVersion":1,"captureId":"capture","networkGeneration":1,"privateKey":"secret"}`,
		`{"schemaVersion":1,"captureId":"capture","networkGeneration":1,"settings":[]}`, string([]byte{0xff})} {
		if _, c := ParseConfig([]byte(data)); c != InvalidArgument {
			t.Fatalf("invalid config accepted: %v", c)
		}
	}
}

func TestCAMaterialValidation(t *testing.T) {
	_, _, der, key := fixture(t)
	_, _, _, wrongKey := fixture(t)
	for _, pair := range []struct {
		der, key []byte
		now      time.Time
	}{{nil, key, time.Now()}, {der, nil, time.Now()}, {[]byte{1}, key, time.Now()}, {der, wrongKey, time.Now()}, {der, key, time.Now().Add(2 * time.Hour)}, {der, key, time.Now().Add(-2 * time.Hour)}} {
		if _, c := ParseMaterial(pair.der, pair.key, pair.now); c != InvalidArgument {
			t.Fatal(c)
		}
	}
}

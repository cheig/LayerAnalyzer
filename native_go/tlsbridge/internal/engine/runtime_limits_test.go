package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCrossLayerRuntimeCapacityVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/fixtures/socks-nio/runtime-capacity-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectorsFixture struct {
		Vectors []struct {
			Name      string
			Config    json.RawMessage
			Effective SocksRuntimeLimits
		}
	}
	if err := json.Unmarshal(raw, &vectorsFixture); err != nil {
		t.Fatal(err)
	}
	if len(vectorsFixture.Vectors) != 31 {
		t.Fatal(len(vectorsFixture.Vectors))
	}
	_, material, _, _ := fixture(t)
	for _, vector := range vectorsFixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			config, code := ParseConfig(vector.Config)
			if code != OK {
				t.Fatal(code)
			}
			effective, code := config.RuntimeLimits()
			if code != OK || effective != vector.Effective {
				t.Fatal(effective, code)
			}
			manager := NewManager(func(_ context.Context, _ Config, _ Material, _ *Callbacks, runtime *Runtime) (*Session, Code) {
				if runtime.Budget.Limits() != (Limits{Connections: effective.TCP, Handshakes: effective.TLSHandshakes}) {
					t.Fatal(runtime.Budget.Limits())
				}
				return sessionStub(func() {}), OK
			})
			handle, _, _, code := manager.Start(config, material, platformStub{})
			if code != OK {
				t.Fatal(code)
			}
			if code := manager.Stop(handle, time.Second); code != OK {
				t.Fatal(code)
			}
		})
	}
}

func TestRuntimeConfigRejectsPartialUnknownAndMixedSchemas(t *testing.T) {
	base := `{"schemaVersion":2,"captureId":"capacity-fixture","networkGeneration":7,"socksRuntime":{"mode":"NIO","tcp":1024,"udp":256,"authentication":128,"tlsHandshakes":8}}`
	cases := []string{
		strings.Replace(base, `"tcp":1024`, `"tcp":1025`, 1), strings.Replace(base, `"tcp":1024`, `"tcp":65`, 1),
		strings.Replace(base, `"udp":256`, `"udp":512`, 1), strings.Replace(base, `"authentication":128`, `"authentication":129`, 1),
		strings.Replace(base, `"tlsHandshakes":8`, `"tlsHandshakes":9`, 1), strings.Replace(base, `"tlsHandshakes":8`, `"tlsHandshakes":null`, 1),
		strings.Replace(base, `"tlsHandshakes":8`, `"TLSHandshakes":8`, 1), strings.Replace(base, `"tlsHandshakes":8`, `"tlsHandshakes":8,"tcp":64`, 1),
		strings.Replace(base, `"mode":"NIO"`, `"mode":"BLOCKING"`, 1), strings.Replace(base, `"mode":"NIO"`, `"mode":"OTHER"`, 1),
		strings.Replace(base, `"schemaVersion":2`, `"schemaVersion":1`, 1), strings.Replace(base, `"schemaVersion":2`, `"SchemaVersion":2`, 1),
		strings.Replace(base, `"schemaVersion":2`, `"schemaVersion":2,"schemaVersion":2`, 1), strings.Replace(base, `,"tlsHandshakes":8`, ``, 1),
		`{"schemaVersion":2,"captureId":"capacity-fixture","networkGeneration":7}`, `{"schemaVersion":1,"captureId":"capacity-fixture","networkGeneration":7,"socksRuntime":null}`,
	}
	for _, raw := range cases {
		if _, code := ParseConfig([]byte(raw)); code != InvalidArgument {
			t.Fatalf("accepted %s", raw)
		}
	}
	config, mat, _, _ := fixture(t)
	config.SchemaVersion = 2
	config.SocksRuntime = &SocksRuntimeLimits{TCP: 1025, UDP: 64, Authentication: 64, TLSHandshakes: 8}
	called := false
	manager := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		called = true
		return sessionStub(func() {}), OK
	})
	if _, _, _, code := manager.Start(config, mat, platformStub{}); code != InvalidArgument || called {
		t.Fatal(code, called)
	}
}
func TestBudgetBorrowedLeaseValidation(t *testing.T) {
	first, _ := NewBudget(Limits{})
	other, _ := NewBudget(Limits{})
	conn, _ := first.Acquire(ConnectionSlot)
	defer conn.Release()
	handshake, _ := first.Acquire(HandshakeSlot)
	defer handshake.Release()
	if !first.Owns(conn) || other.Owns(conn) || first.Owns(handshake) || first.Owns(nil) {
		t.Fatal("invalid ownership")
	}
	conn.Release()
	if first.Owns(conn) {
		t.Fatal("released lease accepted")
	}
}

// Retired startup requests must fail at the wire boundary, even at the old default tier.
func TestRetiredBlockingRequestsNeverStartOrChangeFrozenLimits(t *testing.T) {
	for _, tcp := range []int{64, 1024} {
		for _, mode := range []string{"BLOCKING", "blocking", "OTHER", " NIO", ""} {
			t.Run(fmt.Sprintf("tcp%d/%q", tcp, mode), func(t *testing.T) {
				wire, err := json.Marshal(map[string]any{
					"mode": mode, "tcp": tcp, "udp": 64, "authentication": 64, "tlsHandshakes": 8,
				})
				if err != nil {
					t.Fatal(err)
				}
				frozen := DefaultSocksRuntimeLimits()
				before := frozen
				if err := json.Unmarshal(wire, &frozen); err == nil {
					t.Fatal("obsolete mode was silently accepted")
				}
				if frozen != before {
					t.Fatalf("rejected request changed frozen limits: %+v", frozen)
				}
				raw, err := json.Marshal(map[string]any{
					"schemaVersion": 2, "captureId": "retired-mode", "networkGeneration": 7,
					"socksRuntime": json.RawMessage(wire),
				})
				if err != nil {
					t.Fatal(err)
				}
				config, code := ParseConfig(raw)
				if code != InvalidArgument {
					t.Fatalf("obsolete startup request returned %v", code)
				}
				_, material, _, _ := fixture(t)
				called := false
				manager := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
					called = true
					return sessionStub(func() {}), OK
				})
				if _, _, _, code := manager.Start(config, material, platformStub{}); code != InvalidArgument || called {
					t.Fatalf("rejected request reached assembly: code=%v called=%v", code, called)
				}
			})
		}
	}
}

func TestRuntimeWireIdentityAndCapacityRoundTrip(t *testing.T) {
	for _, limits := range []SocksRuntimeLimits{
		DefaultSocksRuntimeLimits(),
		{TCP: 1024, UDP: 256, Authentication: 128, TLSHandshakes: 8},
	} {
		raw, err := json.Marshal(limits)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(raw, &wire); err != nil || wire["mode"] != "NIO" || len(wire) != 5 {
			t.Fatalf("incompatible runtime wire identity: %s (%v)", raw, err)
		}
		var decoded SocksRuntimeLimits
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded != limits {
			t.Fatalf("capacity changed during round trip: %+v (%v)", decoded, err)
		}
	}
}

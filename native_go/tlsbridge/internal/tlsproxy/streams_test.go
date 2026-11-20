package tlsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// This file is TLS-217's second acceptance case: on a supported path the engine
// returns the application's own bytes. h1, h2, WebSocket, SSE and gRPC all ride
// the same two-sided TLS relay; the proxy never parses an application byte, so
// what each case proves is that a long stream of that protocol's framing crosses
// the proxy unchanged and once — the relay buffers only its fixed window and
// never rewrites anything (§6.3, §6.5). The bytes are the protocol's framing and
// not live sessions: no server implementation is involved, because the claim is
// about the proxy's byte transparency, which the echo origin measures directly.

// streamPayloads builds one protocol's framing, repeated until it is well past
// the relay's 32 KiB buffer so the case is a long stream and not a single read.
type streamPayloads struct {
	name    string
	message []byte
}

func h1Message() []byte {
	return []byte("GET /stream HTTP/1.1\r\nHost: example.test\r\nAccept: text/event-stream\r\n\r\n")
}

func h2Message() []byte {
	body := []byte("h2 stream payload")
	frame := []byte{0, 0, 0, 0x00, 0x00, 0, 0, 0, 1}
	frame[0] = byte(len(body) >> 16)
	frame[1] = byte(len(body) >> 8)
	frame[2] = byte(len(body))
	return append(frame, body...)
}

func webSocketMessage() []byte {
	body := []byte("websocket frame body")
	frame := []byte{0x82, byte(len(body))}
	return append(frame, body...)
}

func sseMessage() []byte {
	return []byte("event: tick\ndata: {\"seq\":1,\"value\":\"streamed\"}\n\n")
}

func grpcMessage() []byte {
	body := []byte("protobuf-ish gRPC message body")
	prefix := make([]byte, 5)
	prefix[0] = 0 // not compressed
	binary.BigEndian.PutUint32(prefix[1:], uint32(len(body)))
	return append(prefix, body...)
}

// TestALongSupportedStreamReturnsEachApplicationProtocolsOwnBytes drives one
// long stream per protocol through a real intercepted connection — both TLS
// handshakes, the production relay, the fixed buffer — and asserts the origin
// gets exactly what the application sent and the application gets exactly what
// the origin echoed. Nothing is re-framed, split, merged or dropped.
func TestALongSupportedStreamReturnsEachApplicationProtocolsOwnBytes(t *testing.T) {
	cases := []streamPayloads{
		{"h1", h1Message()},
		{"h2", h2Message()},
		{"websocket", webSocketMessage()},
		{"sse", sseMessage()},
		{"grpc", grpcMessage()},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, echoOrigin)

			var payload bytes.Buffer
			// Past 32 KiB (the relay buffer) by a wide margin: a streamed
			// response, not one write.
			for payload.Len() < 96<<10 {
				payload.Write(testCase.message)
			}
			body := payload.Bytes()

			writeErr := make(chan error, 1)
			go func() {
				_, err := relayed.app.conn.Write(body)
				writeErr <- err
			}()
			got := readExactly(t, relayed.app.conn, len(body))
			if err := <-writeErr; err != nil {
				t.Fatalf("writing the %s stream: %v", testCase.name, err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("the %s stream came back changed: %d bytes vs %d", testCase.name, len(got), len(body))
			}

			closeTLS(t, relayed.app.conn)
			result := relayed.wait(t)
			requireClean(t, result)
			if result.BytesToUpstream != int64(len(body)) || result.BytesToDownstream != int64(len(body)) {
				t.Fatalf("relayed %d/%d bytes, want %d each way",
					result.BytesToUpstream, result.BytesToDownstream, len(body))
			}
		})
	}
}

// TestALongStreamSurvivesAQuietPeriod is the WebSocket/gRPC shape §6.5 names: a
// connection that says nothing for a while and then speaks again must not have
// been killed by the handshake budget. The pause is longer than the per-side
// handshake budget this connection was given, so a deadline that had leaked into
// the data path would end the connection here.
func TestALongStreamSurvivesAQuietPeriod(t *testing.T) {
	const handshakeBudget = 300 * time.Millisecond
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, handshakeBudget, echoOrigin)

	first := []byte("first message")
	if _, err := relayed.app.conn.Write(first); err != nil {
		t.Fatalf("writing the first message: %v", err)
	}
	if got := readExactly(t, relayed.app.conn, len(first)); !bytes.Equal(got, first) {
		t.Fatalf("the first message came back as %q", got)
	}

	// Quiet for longer than the handshake budget the connection started with.
	time.Sleep(4 * handshakeBudget)

	second := []byte("a message after the pause")
	if _, err := relayed.app.conn.Write(second); err != nil {
		t.Fatalf("the quiet connection no longer accepts data: %v", err)
	}
	if got := readExactly(t, relayed.app.conn, len(second)); !bytes.Equal(got, second) {
		t.Fatalf("the message after the pause came back as %q", got)
	}

	closeTLS(t, relayed.app.conn)
	requireClean(t, relayed.wait(t))
}

//go:build !tlsprobe

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#include "la_tls_bridge.h"
#include <stdlib.h>
static int callbacks_valid(la_tls_callbacks *c) {
    return c && c->struct_size >= sizeof(la_tls_callbacks) && c->abi_version == LA_TLS_ABI_VERSION &&
        c->prepare_socket && c->resolve_host && c->verify_upstream && c->offer_secret;
}
static int32_t call_prepare(la_tls_callbacks *c, int32_t fd, int64_t g) { return c->prepare_socket(c->context, fd, g); }
static int32_t call_resolve(la_tls_callbacks *c, la_tls_bytes host, int64_t g, uint8_t *out, uint32_t *size) {
    return c->resolve_host(c->context, host, g, out, 16384, size);
}
static int32_t call_verify(la_tls_callbacks *c, la_tls_bytes *chain, uint32_t count, la_tls_bytes id, la_tls_bytes auth, la_tls_bytes version) {
    return c->verify_upstream(c->context, chain, count, id, auth, version);
}
static int32_t call_secret(la_tls_callbacks *c, la_tls_bytes capture, la_tls_bytes connection, la_tls_bytes line) {
    return c->offer_secret(c->context, capture, connection, line);
}
*/
import "C"

import (
	"encoding/json"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/engine/assembly"
)

// The production factory is the assembled connection engine (TLS-213). Loading
// the library still creates no listener, no CA, no callback and no engine
// worker; only an explicit la_tls_start with a frozen, enabled policy builds
// one run, and it opens nothing until then.
var production = engine.NewManager(assembly.Factory())

type allocation struct {
	data unsafe.Pointer
	size uint32
}

var buffers = struct {
	sync.Mutex
	next      uint64
	allocated uint64
	freed     uint64
	entries   map[uint64]allocation
}{entries: make(map[uint64]allocation)}

func empty(out *C.la_tls_buffer) bool {
	return out != nil && out.data == nil && out.len == 0 && out.allocation_id == 0
}
func allocate(data []byte, out *C.la_tls_buffer) engine.Code {
	if !empty(out) || len(data) == 0 || len(data) > C.LA_TLS_MAX_JSON {
		return engine.InvalidArgument
	}
	p := C.CBytes(data)
	if p == nil {
		return engine.IOError
	}
	buffers.Lock()
	defer buffers.Unlock()
	if buffers.next == ^uint64(0) {
		C.free(p)
		return engine.CapacityExceeded
	}
	buffers.next++
	buffers.allocated++
	buffers.entries[buffers.next] = allocation{p, uint32(len(data))}
	*out = C.la_tls_buffer{data: (*C.uint8_t)(p), len: C.uint32_t(len(data)), allocation_id: C.uint64_t(buffers.next)}
	return engine.OK
}

func reply(out *C.la_tls_buffer, value map[string]any, code engine.Code) C.int32_t {
	data, err := json.Marshal(value)
	if err != nil {
		return C.int32_t(engine.IOError)
	}
	if status := allocate(data, out); status != engine.OK {
		return C.int32_t(status)
	}
	return C.int32_t(code)
}

func copyInput(in C.la_tls_bytes, max uint32) ([]byte, bool) {
	if in.data == nil || in.len == 0 || uint32(in.len) > max {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(in.data), C.int(in.len)), true
}

//export la_tls_abi_version
func la_tls_abi_version() C.uint32_t { return C.LA_TLS_ABI_VERSION }

//export la_tls_capabilities
func la_tls_capabilities(out *C.la_tls_buffer) C.int32_t {
	r := engine.Envelope(engine.OK)
	r["abiVersion"] = 1
	r["engineReady"] = production.Ready()
	// Real CA generation is installed (TLS-205), so the capability reports what
	// exists, not what a later task will add. It still starts nothing: no
	// listener, no key material and no engine worker is created by this call.
	r["caGenerationReady"] = true
	r["state"] = engine.New
	r["goroutines"] = runtime.NumGoroutine()
	buffers.Lock()
	r["buffersAllocated"], r["buffersFreed"], r["buffersOutstanding"] = buffers.allocated, buffers.freed, len(buffers.entries)
	buffers.Unlock()
	return reply(out, r, engine.OK)
}

//export la_tls_start
func la_tls_start(config, certificate, privateKey C.la_tls_bytes, callbacks *C.la_tls_callbacks, out, token *C.la_tls_buffer) C.int32_t {
	if !empty(out) || !empty(token) || out == token {
		return C.LA_TLS_INVALID_ARGUMENT
	}
	fail := func(code engine.Code) C.int32_t { return reply(out, engine.Envelope(code), code) }
	if C.callbacks_valid(callbacks) == 0 {
		return fail(engine.InvalidArgument)
	}
	configData, ok := copyInput(config, 65536)
	if !ok {
		return fail(engine.InvalidArgument)
	}
	cfg, code := engine.ParseConfig(configData)
	if code != engine.OK {
		return fail(code)
	}
	certData, ok := copyInput(certificate, 65536)
	if !ok {
		return fail(engine.InvalidArgument)
	}
	keyData, ok := copyInput(privateKey, 16384)
	if !ok {
		return fail(engine.InvalidArgument)
	}
	defer clear(keyData)
	material, code := engine.ParseMaterial(certData, keyData, time.Now())
	if code != engine.OK {
		return fail(code)
	}
	handle, port, secretToken, code := production.Start(cfg, material, &platformCallbacks{table: *callbacks})
	if code != engine.OK {
		return fail(code)
	}
	defer clear(secretToken)
	if code = allocate(secretToken, token); code != engine.OK {
		production.Stop(handle, 5*time.Second)
		return fail(code)
	}
	r := engine.Envelope(engine.OK)
	r["engineHandle"] = handle
	r["port"] = port
	status := reply(out, r, engine.OK)
	if status != C.LA_TLS_OK {
		la_tls_free_buffer(token)
		production.Stop(handle, 5*time.Second)
	}
	return status
}

//export la_tls_stop
func la_tls_stop(handle C.uint64_t, timeout C.uint32_t, out *C.la_tls_buffer) C.int32_t {
	if !empty(out) {
		return C.LA_TLS_INVALID_ARGUMENT
	}
	code := production.Stop(uint64(handle), time.Duration(timeout)*time.Millisecond)
	r := engine.Envelope(code)
	if code == engine.OK {
		if final := production.FinalStats(uint64(handle)); final != nil {
			r["finalStats"] = final
		}
	}
	return reply(out, r, code)
}

//export la_tls_poll
func la_tls_poll(handle C.uint64_t, maxEvents C.uint32_t, out *C.la_tls_buffer) C.int32_t {
	r, code := production.Poll(uint64(handle), uint32(maxEvents))
	return reply(out, r, code)
}

//export la_tls_stats
func la_tls_stats(handle C.uint64_t, out *C.la_tls_buffer) C.int32_t {
	// TLS-212: the run's shared capacity budgets and its event-path counters.
	// Same symbol, same envelope; the budget and event objects are additions a
	// reader that only knows "state" simply ignores.
	r, code := production.Stats(uint64(handle))
	return reply(out, r, code)
}

//export la_tls_generate_ca
func la_tls_generate_ca(cert, key *C.la_tls_buffer) C.int32_t {
	if !empty(cert) || !empty(key) || cert == key {
		return C.LA_TLS_INVALID_ARGUMENT
	}
	// One fresh install CA per call, in pure Go, with no listener and no engine
	// state: the caller persists it through the C06 container (TLS-206) and
	// hands it back at start. The two buffers are independent allocations and
	// must be released separately; nothing here is JSON and no leaf key is ever
	// part of the result.
	root, code := certstore.GenerateRoot(time.Now())
	if code != engine.OK {
		return C.int32_t(code)
	}
	certificate, privateKey, code := root.Export()
	if code != engine.OK {
		return C.int32_t(code)
	}
	defer clear(privateKey)
	if status := allocate(certificate, cert); status != engine.OK {
		return C.int32_t(status)
	}
	if status := allocate(privateKey, key); status != engine.OK {
		la_tls_free_buffer(cert)
		return C.int32_t(status)
	}
	return C.LA_TLS_OK
}

//export la_tls_free_buffer
func la_tls_free_buffer(out *C.la_tls_buffer) C.int32_t {
	if out == nil {
		return C.LA_TLS_INVALID_ARGUMENT
	}
	if empty(out) {
		return C.LA_TLS_OK
	}
	buffers.Lock()
	defer buffers.Unlock()
	a, ok := buffers.entries[uint64(out.allocation_id)]
	if !ok || a.data != unsafe.Pointer(out.data) || a.size != uint32(out.len) {
		return C.LA_TLS_INVALID_ARGUMENT
	}
	clear(unsafe.Slice((*byte)(a.data), int(a.size)))
	C.free(a.data)
	delete(buffers.entries, uint64(out.allocation_id))
	buffers.freed++
	*out = C.la_tls_buffer{}
	return C.LA_TLS_OK
}

type platformCallbacks struct{ table C.la_tls_callbacks }

func status(c C.int32_t) engine.Code {
	if c < 0 || c > C.LA_TLS_CAPTURE_CONTEXT_MISSING {
		return engine.IOError
	}
	return engine.Code(c)
}
func cbytes(b []byte) (C.la_tls_bytes, func()) {
	p := C.CBytes(b)
	return C.la_tls_bytes{data: (*C.uint8_t)(p), len: C.uint32_t(len(b))}, func() {
		if p != nil {
			clear(unsafe.Slice((*byte)(p), len(b)))
			C.free(p)
		}
	}
}
func (p *platformCallbacks) PrepareSocket(fd int, generation int64) engine.Code {
	if fd < 0 || fd > 1<<31-1 || generation < 0 {
		return engine.InvalidArgument
	}
	return status(C.call_prepare(&p.table, C.int32_t(fd), C.int64_t(generation)))
}
func (p *platformCallbacks) ResolveHost(host string, generation int64) ([]byte, engine.Code) {
	if len(host) == 0 || len(host) > 253 || generation < 0 {
		return nil, engine.InvalidArgument
	}
	name, release := cbytes([]byte(host))
	defer release()
	out := C.malloc(16384)
	if out == nil {
		return nil, engine.IOError
	}
	defer C.free(out)
	var size C.uint32_t
	code := status(C.call_resolve(&p.table, name, C.int64_t(generation), (*C.uint8_t)(out), &size))
	if code != engine.OK {
		return nil, code
	}
	if size == 0 || size > 16384 {
		return nil, engine.IOError
	}
	return C.GoBytes(out, C.int(size)), engine.OK
}
func (p *platformCallbacks) VerifyUpstream(chain [][]byte, identity, auth, version string) engine.Code {
	if len(chain) == 0 || len(chain) > 16 || len(identity) == 0 || len(identity) > 253 || len(auth) == 0 || len(auth) > 32 || len(version) == 0 || len(version) > 16 {
		return engine.InvalidArgument
	}
	for _, cert := range chain {
		if len(cert) == 0 || len(cert) > 65536 {
			return engine.InvalidArgument
		}
	}
	array := C.malloc(C.size_t(len(chain)) * C.size_t(unsafe.Sizeof(C.la_tls_bytes{})))
	if array == nil {
		return engine.IOError
	}
	defer C.free(array)
	items := unsafe.Slice((*C.la_tls_bytes)(array), len(chain))
	for i, cert := range chain {
		value, release := cbytes(cert)
		defer release()
		items[i] = value
	}
	id, releaseID := cbytes([]byte(identity))
	defer releaseID()
	at, releaseAuth := cbytes([]byte(auth))
	defer releaseAuth()
	tls, releaseTLS := cbytes([]byte(version))
	defer releaseTLS()
	return status(C.call_verify(&p.table, (*C.la_tls_bytes)(array), C.uint32_t(len(chain)), id, at, tls))
}
func (p *platformCallbacks) OfferSecret(capture, connection string, line []byte) engine.Code {
	if !engine.ValidID(capture) || !engine.ValidID(connection) || len(line) == 0 || len(line) > 8192 {
		return engine.InvalidArgument
	}
	cid, cfree := cbytes([]byte(capture))
	defer cfree()
	coid, cofree := cbytes([]byte(connection))
	defer cofree()
	data, dfree := cbytes(line)
	defer dfree()
	return status(C.call_secret(&p.table, cid, coid, data))
}

func main() {}

//go:build tlsprobe

package main

/*
#include <stdlib.h>
#include "tls_probe.h"
static int32_t pair_prepare(la_tls_probe_prepare_socket callback, uintptr_t context, int32_t fd) {
    return callback(context, fd, 0);
}
static int32_t tun_ready(la_tls_probe_tun_ready callback, uintptr_t context, uint16_t port, uint8_t *token, uint32_t len) {
    return callback(context, port, token, len);
}
static void wipe_free(la_tls_probe_bytes *b) {
    volatile uint8_t *p = b->data;
    for (uint32_t i = 0; i < b->len; ++i) p[i] = 0;
    free(b->data); b->data = NULL; b->len = 0;
}
*/
import "C"

import (
	"com.layeranalyzer/tlsbridge/internal/probe"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"sync/atomic"
)

var pairBusy atomic.Bool

//export la_tls_probe_pair_abi_version
func la_tls_probe_pair_abi_version() C.uint32_t { return C.LA_TLS_PAIR_PROBE_ABI_VERSION }

//export la_tls_probe_pair_free
func la_tls_probe_pair_free(out *C.la_tls_probe_pair_result) {
	if out == nil {
		return
	}
	C.wipe_free(&out.metadata)
	C.wipe_free(&out.downstream_keys)
	C.wipe_free(&out.upstream_keys)
}

func pairBytes(data []byte) C.la_tls_probe_bytes {
	if len(data) == 0 {
		return C.la_tls_probe_bytes{}
	}
	return C.la_tls_probe_bytes{data: (*C.uint8_t)(C.CBytes(data)), len: C.uint32_t(len(data))}
}

//export la_tls_probe_pair_run
func la_tls_probe_pair_run(protocol C.uint32_t, rejectRoot C.uint32_t, callback C.la_tls_probe_prepare_socket, callbackContext C.uintptr_t, out *C.la_tls_probe_pair_result) C.int32_t {
	return runPair(protocol, rejectRoot, callback, nil, callbackContext, out)
}

//export la_tls_probe_tun_abi_version
func la_tls_probe_tun_abi_version() C.uint32_t { return C.LA_TLS_TUN_PROBE_ABI_VERSION }

//export la_tls_probe_tun_run
func la_tls_probe_tun_run(protocol C.uint32_t, callback C.la_tls_probe_prepare_socket, ready C.la_tls_probe_tun_ready, callbackContext C.uintptr_t, out *C.la_tls_probe_pair_result) C.int32_t {
	if ready == nil {
		return C.LA_TLS_PROBE_INVALID_ARGUMENT
	}
	return runPair(protocol, 0, callback, ready, callbackContext, out)
}

func runPair(protocol C.uint32_t, rejectRoot C.uint32_t, callback C.la_tls_probe_prepare_socket, ready C.la_tls_probe_tun_ready, callbackContext C.uintptr_t, out *C.la_tls_probe_pair_result) C.int32_t {
	if out == nil {
		return C.LA_TLS_PROBE_INVALID_ARGUMENT
	}
	*out = C.la_tls_probe_pair_result{}
	if protocol > 2 || rejectRoot > 1 || callback == nil {
		return C.LA_TLS_PROBE_INVALID_ARGUMENT
	}
	if !pairBusy.CompareAndSwap(false, true) {
		return C.LA_TLS_PROBE_CAPACITY_EXCEEDED
	}
	defer pairBusy.Store(false)
	opts := probe.PairOptions{Version: tls.VersionTLS13, ALPN: "http/1.1", RejectUpstreamRoot: rejectRoot == 1}
	if protocol == 0 {
		opts.Version = tls.VersionTLS12
	}
	if protocol == 2 {
		opts.ALPN = "h2"
	}
	if ready != nil {
		opts.TunReady = func(port int, token []byte) error {
			data := pairBytes(token)
			defer C.wipe_free(&data)
			if C.tun_ready(ready, callbackContext, C.uint16_t(port), data.data, data.len) != C.LA_TLS_PROBE_OK {
				return probe.Cancelled
			}
			return nil
		}
	}
	r, err := probe.RunTLSPair(context.Background(), opts, func(fd uintptr, _ int64) probe.Status {
		return probe.Status(C.pair_prepare(callback, callbackContext, C.int32_t(fd)))
	}, nil)
	defer clear(r.DownstreamKeys)
	defer clear(r.UpstreamKeys)
	var code any
	if err != nil {
		code = "IO_ERROR"
		if err.Error() == "UPSTREAM_CERT_INVALID" {
			code = "UPSTREAM_CERT_INVALID"
		}
		if errors.Is(err, probe.ProtectFailed) {
			code = "PROTECT_FAILED"
		}
	}
	var message any
	if err != nil {
		message = "TLS pair probe failed"
	}
	data, marshalErr := json.Marshal(struct {
		probe.PairResult
		SchemaVersion int  `json:"schemaVersion"`
		Success       bool `json:"success"`
		ErrorCode     any  `json:"errorCode"`
		Error         any  `json:"error"`
	}{r, 1, err == nil, code, message})
	if marshalErr != nil {
		return C.LA_TLS_PROBE_IO_ERROR
	}
	out.metadata = pairBytes(data)
	out.downstream_keys = pairBytes(r.DownstreamKeys)
	out.upstream_keys = pairBytes(r.UpstreamKeys)
	// Transport success means buffers are valid; actual experiment status is JSON.
	return C.LA_TLS_PROBE_OK
}

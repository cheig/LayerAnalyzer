//go:build tlsprobe

package main

/*
#include "tls_probe.h"
static int32_t invoke_prepare(la_tls_probe_prepare_socket callback, uintptr_t context,
                             int32_t fd, int64_t generation) {
    return callback(context, fd, generation);
}
*/
import "C"

import (
	"context"
	"sync/atomic"
	"time"
	"unsafe"

	"com.layeranalyzer/tlsbridge/internal/probe"
)

var socketBusy atomic.Bool

//export la_tls_probe_socket_abi_version
func la_tls_probe_socket_abi_version() C.uint32_t { return C.LA_TLS_SOCKET_PROBE_ABI_VERSION }

//export la_tls_probe_socket_dial
func la_tls_probe_socket_dial(ip *C.uint8_t, length C.uint32_t, port C.uint16_t, generation C.int64_t, timeoutMillis C.uint32_t, callback C.la_tls_probe_prepare_socket, callbackContext C.uintptr_t, out *C.la_tls_probe_socket_result) C.int32_t {
	if out == nil {
		return C.LA_TLS_PROBE_INVALID_ARGUMENT
	}
	*out = C.la_tls_probe_socket_result{}
	if ip == nil || length == 0 || length > 45 || callback == nil {
		return C.LA_TLS_PROBE_INVALID_ARGUMENT
	}
	if !socketBusy.CompareAndSwap(false, true) {
		return C.LA_TLS_PROBE_CAPACITY_EXCEEDED
	}
	defer socketBusy.Store(false)
	r, status := probe.DialSocket(context.Background(), C.GoStringN((*C.char)(unsafe.Pointer(ip)), C.int(length)), int(port), int64(generation), time.Duration(timeoutMillis)*time.Millisecond,
		func(fd uintptr, generation int64) probe.Status {
			return probe.Status(C.invoke_prepare(callback, callbackContext, C.int32_t(fd), C.int64_t(generation)))
		})
	out.control_calls = C.uint32_t(r.ControlCalls)
	if r.Connected {
		out.connected = 1
	}
	out.server_accept_sequence = C.uint32_t(r.ServerAcceptSequence)
	return C.int32_t(status)
}

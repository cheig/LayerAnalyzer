//go:build tlsprobe

// Package main is the P0 c-shared smoke library, not the production TLS engine.
package main

/*
#include "tls_probe.h"
*/
import "C"

var smoke = smokeRegistry{}

//export la_tls_probe_abi_version
func la_tls_probe_abi_version() C.uint32_t {
	return C.LA_TLS_PROBE_ABI_VERSION
}

//export la_tls_probe_start
func la_tls_probe_start(outHandle *C.uint64_t) C.int32_t {
	if outHandle == nil {
		return C.LA_TLS_PROBE_INVALID_ARGUMENT
	}
	*outHandle = 0
	handle, status := smoke.start()
	*outHandle = C.uint64_t(handle)
	return C.int32_t(status)
}

//export la_tls_probe_stop
func la_tls_probe_stop(handle C.uint64_t) C.int32_t {
	return C.int32_t(smoke.stop(uint64(handle)))
}

//export la_tls_probe_active_handles
func la_tls_probe_active_handles() C.uint32_t {
	return C.uint32_t(smoke.activeHandles())
}

func main() {}

#ifndef LAYANALYZER_TLS_PROBE_H
#define LAYANALYZER_TLS_PROBE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// P0 only. TLS-201 will define a separate production ABI.
#define LA_TLS_PROBE_ABI_VERSION 1u
enum {
    LA_TLS_PROBE_OK = 0,
    LA_TLS_PROBE_INVALID_ARGUMENT = 1,
    LA_TLS_PROBE_NOT_READY = 2,
    LA_TLS_PROBE_CAPACITY_EXCEEDED = 3,
    LA_TLS_PROBE_IO_ERROR = 4,
    LA_TLS_PROBE_PROTECT_FAILED = 5,
    LA_TLS_PROBE_NETWORK_CHANGED = 6,
    LA_TLS_PROBE_STALE_GENERATION = 7,
    LA_TLS_PROBE_CANCELLED = 8
};

uint32_t la_tls_probe_abi_version(void);
// One active engine. Always clears *out_handle before attempting start.
// No sockets, worker goroutines, callbacks, secrets or TLS operations are started.
int32_t la_tls_probe_start(uint64_t *out_handle);
// Previously issued handles may be stopped again, including after a new start.
// Zero and never-issued handles fail. A stale stop never closes a newer handle.
int32_t la_tls_probe_stop(uint64_t handle);
uint32_t la_tls_probe_active_handles(void);

// Optional TLS-005 extension. Smoke ABI v1 remains compatible with TLS-003/004.
#define LA_TLS_SOCKET_PROBE_ABI_VERSION 1u
typedef int32_t (*la_tls_probe_prepare_socket)(uintptr_t context, int32_t fd, int64_t generation);
typedef struct {
    uint32_t control_calls;
    uint32_t connected;
    uint32_t server_accept_sequence;
} la_tls_probe_socket_result;
uint32_t la_tls_probe_socket_abi_version(void);
// Blocking, one in flight, max 10 seconds for connect + fixture reply. Callback
// completes before connect; Go closes the socket before returning. No retained
// callback/context/IP pointer, no Go pointer crosses the boundary. Literal IP only.
int32_t la_tls_probe_socket_dial(uint8_t *ip, uint32_t ip_len, uint16_t port,
    int64_t generation, uint32_t timeout_millis, la_tls_probe_prepare_socket callback,
    uintptr_t context, la_tls_probe_socket_result *out_result);

// TLS-006 optional lab extension. Three distinct buffers: ordinary metadata,
// downstream secrets and upstream secrets. All allocated in C, caller frees the
// entire result with pair_free (which zeroes buffers). No secrets in JSON/logs.
#define LA_TLS_PAIR_PROBE_ABI_VERSION 1u
typedef struct { uint8_t *data; uint32_t len; } la_tls_probe_bytes;
typedef struct {
    la_tls_probe_bytes metadata;
    la_tls_probe_bytes downstream_keys;
    la_tls_probe_bytes upstream_keys;
} la_tls_probe_pair_result;
uint32_t la_tls_probe_pair_abi_version(void);
// protocol: 0=TLS1.2/h1, 1=TLS1.3/h1, 2=TLS1.3/h2. reject_root: 0/1.
// One in flight, fixed self-contained loopback fixtures, max 10s network budget.
// Callback is synchronous before the Go upstream socket connects, generation=0.
int32_t la_tls_probe_pair_run(uint32_t protocol, uint32_t reject_root,
    la_tls_probe_prepare_socket callback, uintptr_t context, la_tls_probe_pair_result *out);
void la_tls_probe_pair_free(la_tls_probe_pair_result *result);

// TLS-008 lab extension, never production ABI. ready must install/start the
// test VPN synchronously before the unprotected fixture client is created.
// Token is raw 32 bytes, borrowed for the callback only; never log or persist it.
#define LA_TLS_TUN_PROBE_ABI_VERSION 1u
typedef int32_t (*la_tls_probe_tun_ready)(uintptr_t context, uint16_t port, uint8_t *token, uint32_t token_len);
uint32_t la_tls_probe_tun_abi_version(void);
int32_t la_tls_probe_tun_run(uint32_t protocol, la_tls_probe_prepare_socket prepare,
    la_tls_probe_tun_ready ready, uintptr_t context, la_tls_probe_pair_result *out);

// The process owns the Go runtime. Do not dlclose this library after loading it.
// Start/stop only manage the smoke handle; they do not start/stop the Go runtime.

#ifdef __cplusplus
}
#endif
#endif

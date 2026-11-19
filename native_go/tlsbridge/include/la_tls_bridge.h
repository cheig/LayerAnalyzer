#ifndef LA_TLS_BRIDGE_H
#define LA_TLS_BRIDGE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define LA_TLS_ABI_VERSION 1u
#define LA_TLS_MAX_JSON 262144u

/* Numeric values are permanent ABI, independent of the P0 smoke interface. */
enum la_tls_status {
    LA_TLS_OK = 0, LA_TLS_INVALID_ARGUMENT = 1, LA_TLS_NOT_READY = 2,
    LA_TLS_UNSUPPORTED = 3, LA_TLS_STALE_GENERATION = 4, LA_TLS_CANCELLED = 5,
    LA_TLS_IO_ERROR = 6, LA_TLS_CAPACITY_EXCEEDED = 7, LA_TLS_PROTECT_FAILED = 8,
    LA_TLS_NETWORK_CHANGED = 9, LA_TLS_UPSTREAM_CERT_INVALID = 10,
    LA_TLS_DOWNSTREAM_TLS_REJECTED = 11, LA_TLS_SECRETS_INCOMPLETE = 12,
    LA_TLS_CAPTURE_CONTEXT_MISSING = 13
};

/* Borrowed for the duration of a call; no implicit NUL termination. */
typedef struct { const uint8_t *data; uint32_t len; } la_tls_bytes;
/* Owned C allocation, never a Go pointer. Release even on operation failure.
 * allocation_id prevents stale copies freeing a reused address. Do not modify
 * fields; free_buffer clears them and accepts an already cleared buffer. */
typedef struct { uint8_t *data; uint32_t len; uint64_t allocation_id; } la_tls_buffer;

/* All callbacks are synchronous, may arrive on Go threads, and must not call
 * start/stop recursively. context is an opaque C/JNI value, never a Go pointer.
 * Go owns socket fds; prepare_socket must protect/bind before returning.
 * resolve_host writes a schemaVersion=1 JSON envelope with addresses:[IP,...]
 * into caller storage (capacity 16 KiB); no host allocation crosses the ABI.
 * verify_upstream receives DER certificates and returns a fixed status code.
 * offer_secret copies/enqueues bytes only; OK means accepted, not persisted.
 * Caller retains table targets/context until start fails or stop succeeds.
 * A stop timeout is NOT_READY: retain context and retry stop until OK. */
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uintptr_t context;
    int32_t (*prepare_socket)(uintptr_t, int32_t, int64_t);
    int32_t (*resolve_host)(uintptr_t, la_tls_bytes, int64_t, uint8_t *, uint32_t, uint32_t *);
    int32_t (*verify_upstream)(uintptr_t, const la_tls_bytes *, uint32_t,
                               la_tls_bytes, la_tls_bytes, la_tls_bytes);
    int32_t (*offer_secret)(uintptr_t, la_tls_bytes, la_tls_bytes, la_tls_bytes);
} la_tls_callbacks;

uint32_t la_tls_abi_version(void);
/* capabilities does not start a service. start config is UTF-8 JSON:
 * {schemaVersion:1,captureId:<ASCII ID 1..128>,networkGeneration:<nonnegative>,
 *  settings?:<frozen TLS policy object>} selects legacy low defaults. New callers
 * use schemaVersion:2 and require socksRuntime:{mode:"NIO",tcp:64|128|256|512|
 * 1024,udp:64|128|256,authentication:64|128,tlsHandshakes:8}. The wire mode is a
 * fixed identity, not a selector: BLOCKING requests return INVALID_ARGUMENT,
 * including at 64/64/64. v1 defaults to NIO 64/64/64/8 and rejects socksRuntime;
 * v2 rejects missing/partial limits. Historical reports do not configure starts.
 * No token or CA/private key in JSON. ABI, LAT1 and response schemas unchanged.
 * Valid but unassembled production components return NOT_READY, no handle.
 * start JSON success contains engineHandle and port; gateway token is a
 * separate owned buffer, base64url without padding (32 random bytes before
 * encoding), only for the caller's in-memory gateway transport. */
int32_t la_tls_capabilities(la_tls_buffer *json);
int32_t la_tls_start(la_tls_bytes config, la_tls_bytes certificate_der,
                     la_tls_bytes private_key_pkcs8, la_tls_callbacks *callbacks,
                     la_tls_buffer *json, la_tls_buffer *gateway_token);
/* timeout_ms: 1..5000; handles fit positive signed Java Long. Repeated stop of
 * an issued handle is OK; stale stats fail STALE_GENERATION. Poll may drain the
 * last stopped run's bounded unread events (state STOPPED), then becomes stale;
 * the next accepted start also expires those events. Successful stop
 * may append finalStats: counts only after join, retained for one run until next
 * start. Missing finalStats is unknown, not a zero-resource assertion. */
int32_t la_tls_stop(uint64_t handle, uint32_t timeout_ms, la_tls_buffer *json);
int32_t la_tls_poll(uint64_t handle, uint32_t max_events, la_tls_buffer *json);
int32_t la_tls_stats(uint64_t handle, la_tls_buffer *json);
/* Generates one fresh install CA (RSA 3072) as two independent owned buffers:
 * the public certificate in DER and the private key in PKCS#8. Release each with
 * la_tls_free_buffer, including after a failure. Never reports success with an
 * empty buffer and never returns key material as JSON. */
int32_t la_tls_generate_ca(la_tls_buffer *certificate_der, la_tls_buffer *private_key_pkcs8);
int32_t la_tls_free_buffer(la_tls_buffer *buffer);

#ifdef __cplusplus
}
#endif
#endif

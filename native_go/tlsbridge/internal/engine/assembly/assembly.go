// Package assembly wires one engine run's parts together (TLS-213).
//
// This is the only place in the module that may import the decision maker and
// the connection state machine at once, because Go forbids the cycle
// tlsproxy → policy. Everything it builds is per run: the CA-backed leaf store,
// the platform dialer, the capture's keylog sink, the connection pipeline and
// the authenticated loopback gateway that hands it connections.
//
// It opens nothing until the factory is called. Loading the library, querying
// capabilities and stopping a stopped engine all leave the device's ports,
// sockets and workers untouched, which is what TLS-201 required and what this
// package must not undo.
package assembly

import (
	"bytes"
	"context"
	"net"
	"sync"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/gateway"
	"com.layeranalyzer/tlsbridge/internal/policy"
	"com.layeranalyzer/tlsbridge/internal/secrets"
	"com.layeranalyzer/tlsbridge/internal/tlsproxy"
	"com.layeranalyzer/tlsbridge/internal/uplink"
)

// Factory returns the production factory. Handing it to engine.NewManager is
// the whole wiring step: engine.Manager owns the lifecycle, this function owns
// what one RUNNING run is made of.
func Factory() engine.Factory { return assemble }

func assemble(ctx context.Context, config engine.Config, material engine.Material,
	callbacks *engine.Callbacks, runtime *engine.Runtime) (*engine.Session, engine.Code) {
	if ctx == nil || callbacks == nil || runtime == nil || runtime.Budget == nil || runtime.Events == nil {
		return nil, engine.InvalidArgument
	}
	// A run with no frozen interception policy is not a run. The settings object
	// is where Kotlin freezes the user's scope (C04); without one the engine
	// would open a loopback listener and report READY for a capture that can
	// never decrypt anything, which is exactly the useless port TLS-201 forbids
	// announcing. It is also the honest answer for a policy whose enabled flag
	// is false: the caller turned interception off.
	if len(bytes.TrimSpace(config.Settings)) == 0 {
		return nil, engine.NotReady
	}
	frozen, code := policy.ParsePolicy(config.Settings)
	if code != engine.OK {
		return nil, code
	}
	if !frozen.Enabled() {
		return nil, engine.NotReady
	}
	frozenRuntime, code := config.RuntimeLimits()
	if code != engine.OK || runtime.Budget.ConnectionCapacity() != frozenRuntime.TCP {
		return nil, engine.InvalidArgument
	}
	generation := *config.NetworkGeneration

	// The CA the platform persisted is adopted rather than generated here: its
	// key belongs to the encrypted container (TLS-206), and a leaf is issued
	// from it per connection. The store holds no leaf private key of its own and
	// hands none out.
	leaves := certstore.NewStore(certstore.DefaultCapacity)
	if code := leaves.SetRoot(material.Certificate, material.Signer); code != engine.OK {
		return nil, code
	}
	// One dialer for every real outbound socket: the gateway's hop to the origin
	// and the fallback's replacement socket both protect, bind and connect on
	// the captured network, through the same admission-gated callbacks.
	dialer, code := uplink.New(callbacks, generation, 0)
	if code != engine.OK {
		return nil, code
	}
	sink, code := secrets.NewSink(config.CaptureID, callbacks, secrets.Limits{})
	if code != engine.OK {
		return nil, code
	}
	pipeline, code := tlsproxy.NewPipeline(tlsproxy.Options{
		CaptureID: config.CaptureID,
		Policy:    frozen.VPNRouter(),
		Leaves:    leaves,
		Gate:      callbacks,
		Dialer:    dialer,
		Secrets:   sink,
		Budget:    runtime.Budget,
		Events:    runtime.Events,
	})
	if code != engine.OK {
		closeSecrets(sink)
		return nil, code
	}

	server, code := gateway.Start(ctx, gateway.Options{
		CaptureID:         config.CaptureID,
		NetworkGeneration: generation,
		// Candidate connections acquire this same budget before dial and reuse
		// the lease in the pipeline. Kotlin counts direct + candidate TCP; these
		// populations overlap. VPN scope applies before gateway admission.
		Capacity:               runtime.Budget.ConnectionCapacity(),
		AuthenticationCapacity: frozenRuntime.Authentication,
		Budget:                 runtime.Budget,
		Dial: func(dialCtx context.Context, metadata gateway.Metadata) (net.Conn, engine.Code) {
			return dialer.Dial(dialCtx, metadata.Destination)
		},
		Handle: func(flowCtx context.Context, metadata gateway.Metadata, downstream, upstream net.Conn) {
			pipeline.Handle(flowCtx, tlsproxy.Request{
				ConnectionID:      metadata.ConnectionID,
				ConnectionLease:   metadata.ConnectionLease,
				Destination:       metadata.Destination,
				NetworkGeneration: metadata.NetworkGeneration,
				Downstream:        downstream,
				Upstream:          upstream,
			})
		},
	})
	if code != engine.OK {
		// A factory must roll back what it built before returning a failure: the
		// manager has no session to close, so nothing else can reap the sink's
		// consumer goroutine.
		closeSecrets(sink)
		return nil, code
	}
	return &engine.Session{
		Port:  server.Port(),
		Token: server.Token(),
		Close: func() { shutdown(server, sink) },
		GatewayStats: func() map[string]any {
			s := server.Stats()
			return map[string]any{
				"authenticationFailures": s.AuthenticationFailures, "authentication": s.Authentication,
				"active": s.Active, "acceptedCurrent": s.AcceptedCurrent,
				"authenticationLimit": s.AuthenticationLimit, "activeLimit": s.ActiveLimit,
				"acceptedLimit": s.AcceptedLimit, "socketLimit": s.SocketLimit,
				"peakAuthentication": s.PeakAuthentication, "peakActive": s.PeakActive,
				"peakAccepted": s.PeakAccepted, "accepted": s.Accepted, "authenticated": s.Authenticated,
				"rejectedBeforeAuthentication": s.RejectedBeforeAuthentication,
				"rejectedActiveCapacity":       s.RejectedActiveCapacity,
				"dialAttempts":                 s.DialAttempts, "dialFailures": s.DialFailures, "ready": s.Ready,
			}
		},
		Metrics: func() engine.RuntimeMetrics {
			cache := leaves.Stats()
			secret := sink.Stats()
			probe := pipeline.ProbeStats()
			return engine.RuntimeMetrics{
				CertificateCacheMisses:           cache.Misses,
				CertificateCacheEvictions:        cache.Evictions,
				CertificateCachePeakEntries:      cache.PeakCached,
				CertificateIssuances:             cache.Issued,
				CertificateIssueFailures:         cache.Failed,
				CertificateIssuancesInFlight:     cache.InFlight,
				CertificateIssuancesPeakInFlight: cache.PeakInFlight,
				CertificateIssueWaiters:          cache.Waiters,
				CertificateIssuePeakWaiters:      cache.PeakWaiters,
				CertificateIssuesShared:          cache.Shared,
				GoSecretsQueueRecords:            secret.PendingRecords,
				GoSecretsQueuePeakBytes:          secret.PeakPendingBytes,
				GoSecretsQueuePeakRecords:        secret.PeakPendingRecords,
				GoSecretsInFlightBytes:           secret.InFlightBytes,
				GoSecretsPeakRetainedBytes:       secret.PeakRetainedBytes,
				GoSecretsQueueLimitBytes:         secret.QueueLimitBytes,
				GoSecretsOffered:                 secret.Offered,
				GoSecretsAccepted:                secret.Accepted,
				GoSecretsRejected:                secret.Rejected,
				GoSecretsDropped:                 secret.Dropped,
				GoSecretsIncomplete:              secret.Incomplete,
				GoSecretsSettleWaiters:           secret.SettleWaiters,
				GoSecretsPeakSettleWaiters:       secret.PeakSettleWaiters,
				GoSecretsSettleTimeouts:          secret.SettleTimeouts,
				GoSecretsDrainTimeouts:           secret.DrainTimeouts,
				ProbesActive:                     probe.Active,
				ProbesPeakActive:                 probe.PeakActive,
				ProbesStarted:                    probe.Started,
				ProbesFinished:                   probe.Finished,
				ProbesIncomplete:                 probe.Incomplete,
				ProbePrefixCapacityBytes:         probe.PrefixCapacityBytes,
				ProbePeakPrefixCapacityBytes:     probe.PeakPrefixCapacityBytes,
				ProbePrefixCapacityLimitBytes:    probe.PrefixCapacityLimitBytes,

				CertificateCacheEntries: cache.Cached,
				CertificateCacheHits:    cache.Hits,
				GoSecretsQueueBytes:     secret.PendingBytes,
			}
		},
	}, engine.OK
}

// shutdown ends one run in the order that cannot lose a connection: the gateway
// first, so no new flow is admitted and the active ones are cancelled and
// joined, and the sinks afterwards, so what they already accepted is accounted
// for. The two are waited on together because neither needs the other to finish
// and a stop path must not pay for both.
func shutdown(server *gateway.Server, sink *secrets.Sink) {
	var waiting sync.WaitGroup
	waiting.Add(2)
	go func() {
		defer waiting.Done()
		server.Close()
	}()
	go func() {
		defer waiting.Done()
		closeSecrets(sink)
	}()
	waiting.Wait()
}

// closeSecrets reaps the capture's secret path under C10's stop bound. The sink
// never waits without one: records still undelivered when it expires are
// reported as incomplete rather than claimed.
func closeSecrets(sink *secrets.Sink) {
	ctx, cancel := context.WithTimeout(context.Background(), secrets.DefaultDrainTimeout)
	defer cancel()
	sink.Drain(ctx)
}

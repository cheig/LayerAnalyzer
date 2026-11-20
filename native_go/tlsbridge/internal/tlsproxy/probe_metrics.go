package tlsproxy

import "sync"

// ProbeStats counts current prefix backing arrays through replay or Handle's
// joined cleanup, including passthrough. It excludes scanner/body copies, old/new
// allocation overlap, transient parsing allocations, and Go allocator overhead.
type ProbeStats struct {
	Active                   int    `json:"active"`
	PeakActive               int    `json:"peakActive"`
	Started                  uint64 `json:"started"`
	Finished                 uint64 `json:"finished"`
	Incomplete               uint64 `json:"incomplete"`
	PrefixCapacityBytes      int    `json:"prefixCapacityBytes"`
	PeakPrefixCapacityBytes  int    `json:"peakPrefixCapacityBytes"`
	PrefixCapacityLimitBytes int    `json:"prefixCapacityLimitBytes"`
}

type probeMetrics struct {
	mu    sync.Mutex
	stats ProbeStats
}

type prefixReservation struct {
	metrics *probeMetrics
	bytes   int
	once    sync.Once
}

func (m *probeMetrics) begin() *prefixReservation {
	m.mu.Lock()
	m.stats.Active++
	m.stats.Started++
	m.stats.PeakActive = max(m.stats.PeakActive, m.stats.Active)
	m.mu.Unlock()
	return &prefixReservation{metrics: m}
}

func (r *prefixReservation) capacity(bytes int) {
	m := r.metrics
	m.mu.Lock()
	m.stats.PrefixCapacityBytes += bytes - r.bytes
	r.bytes = bytes
	m.stats.PeakPrefixCapacityBytes = max(m.stats.PeakPrefixCapacityBytes, m.stats.PrefixCapacityBytes)
	m.mu.Unlock()
}

func (r *prefixReservation) release() {
	r.once.Do(func() {
		m := r.metrics
		m.mu.Lock()
		m.stats.PrefixCapacityBytes -= r.bytes
		m.mu.Unlock()
	})
}

func (m *probeMetrics) finished(outcome Outcome) {
	m.mu.Lock()
	m.stats.Active--
	m.stats.Finished++
	if outcome.Verdict == VerdictIncomplete {
		m.stats.Incomplete++
	}
	m.mu.Unlock()
}

func (p *Pipeline) ProbeStats() ProbeStats {
	if p == nil {
		return ProbeStats{}
	}
	p.probes.mu.Lock()
	defer p.probes.mu.Unlock()
	stats := p.probes.stats
	stats.PrefixCapacityLimitBytes = p.budget.ConnectionCapacity() * p.probe.normalize().MaxPrefixBytes
	return stats
}

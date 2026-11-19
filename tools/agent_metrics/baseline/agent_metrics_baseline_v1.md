# Agent run-metrics baseline v1 (synthetic fixtures — OPT-EVAL-04-02)

> **数据来源 / data source**: every aggregated row comes from the **synthetic**
> JVM-mock-run fixture under `tools/agent_metrics/samples/` (hand-written JSONL,
> modelled on the two OPT-EVAL-04-01 `AgentLoopTest` RunMetrics cases).
> **这不是真机基线 / this is NOT a real-device baseline.** The device baseline is
> produced after pulling `agent_logs/` from a device and re-running the exact
> same command (see `tools/agent_metrics/README.md`).

- Input: `tools/agent_metrics/samples` (2 jsonl files: agent-diagnostics-1757000000000.jsonl, agent-diagnostics.jsonl)
- Lines: 15 parsed, 0 malformed (skipped), 2 blank, 0 run-record lines and 0 other-schema lines skipped, 0 events without runId ignored
- Runs: 5 distinct runIds in event lines, 5 with a RunMetrics event; 1 run(s) predate the OPT-EVAL-04-01 fields and are excluded from those denominators
- Terminal run status: failed 1 · completed 4

## Quality metrics

| metric | source | runs reporting | value |
|---|---|---|---|
| `citationRejectionRate` | OPT-EVAL-04-01 | 4/5 (1 missing) | mean 0.2188 · median 0.1875 · max 0.5000 |
| `revisionTriggered` | OPT-EVAL-04-01 | 4/5 (1 missing) | 2/4 (50.00%) |
| `confidenceDistribution` | OPT-EVAL-04-01 | 4/5 (1 missing) | High 4 · Medium 4 · Low 1 · Unknown 1 (total 10 findings) |
| `historyCompactedAtEntry` | pre-EVAL-04 | 5/5 | 1/5 (20.00%) |

## Existing run metrics (per-run means)

| metric | unit | runs reporting | mean | sum | min | max |
|---|---|---|---:|---:|---:|---:|
| `negativePolarityDeclared` | findings | 4/5 (1 missing) | 2 | 8 | 1 | 3 |
| `negativePolarityConflict` | rejections | 4/5 (1 missing) | 0.50 | 2 | 0 | 1 |
| `planCoverageGaps` | checks | 4/5 (1 missing) | 1 | 4 | 0 | 2 |
| `signalCoverageGaps` | signals | 4/5 (1 missing) | 0.75 | 3 | 0 | 2 |
| `bootstrapToolCount` | calls | 5/5 | 1.80 | 9 | 1 | 3 |
| `bootstrapResultBytes` | bytes | 5/5 | 1966.80 | 9834 | 1024 | 3072 |
| `bootstrapDurationMillis` | ms | 5/5 | 1020 | 5100 | 700 | 1500 |
| `modelRequestsBeforeFirstEvidence` | calls | 5/5 | 1.40 | 7 | 1 | 2 |
| `modelRequestCount` | calls | 5/5 | 4.40 | 22 | 3 | 6 |
| `logicalModelRequestCount` | calls | 5/5 | 3.80 | 19 | 3 | 5 |
| `planStepsCompleted` | steps | 5/5 | 1.40 | 7 | 0 | 3 |
| `planStepsTotal` | steps | 5/5 | 2 | 10 | 0 | 4 |
| `runElapsedMillis` | ms | 5/5 | 186800 | 934000 | 90000 | 300000 |

Derived **plan step completion rate**: `7` completed of `10` declared plan steps = **70.00%**.

Derived **polarity conflict rate** (OPT-VAL-04-03): `2` `polarity_claim_conflict` rejections over `8` declared-negative findings = **25.00%**.

## Per-run detail

runId is replaced by a truncated SHA-256 hash (privacy red line: no raw ids in reports).

| run | status | citationRejectionRate | revisionTriggered | H/M/L/U findings | modelReq (logical) | plan steps | elapsed ms |
|---|---|---|---|---|---|---|---:|
| `440c9a5b84` | completed | 0.5000 | yes | 0/1/0/0 | 4 (3) | 2/2 | 184000 |
| `50d4d074ef` | failed | — | — | — | 6 (5) | 1/3 | 300000 |
| `5344cc4079` | completed | 0.1250 | no | 1/2/0/1 | 4 (4) | 1/1 | 90000 |
| `8179d53a90` | completed | 0.0000 | no | 1/0/0/0 | 3 (3) | 0/0 | 120000 |
| `910b6ae1a5` | completed | 0.2500 | yes | 2/1/1/0 | 5 (4) | 3/4 | 240000 |

## Definitions

- `citationRejectionRate` (rate, OPT-EVAL-04-01): rejected / submitted citations across all validation rounds of the run; 0 when nothing was submitted
- `revisionTriggered` (flag, OPT-EVAL-04-01): validator rejections ever bought a revision turn
- `confidenceDistribution` (histogram, OPT-EVAL-04-01): findings per confidence level in the final (or most recent) validated report
- `negativePolarityDeclared` (int, OPT-VAL-04-03): findings that declared polarity=Negative, summed across the run's validation rounds
- `negativePolarityConflict` (int, OPT-VAL-04-03): polarity_claim_conflict rejections raised when a Positive/Neutral declaration met an absence-claiming observation, summed across rounds
- `planCoverageGaps` (int, OPT-VAL-01-02): playbook checks still uncovered when the run's report was accepted (incl. the unattributable degrade-to-limitation path); 0 on gated runs without gaps and on valve-off runs
- `signalCoverageGaps` (int, OPT-VAL-02-03): host-enumerated baseline signals still unaddressed when the run's report was accepted (incl. the limitations-only degradation path); 0 when the rule did not run (valve off, no signals enumerated, or no submit accepted)
- `historyCompactedAtEntry` (flag, pre-EVAL-04): replayed history was compacted before the first model call
- `bootstrapToolCount` (int, pre-EVAL-04): bootstrap tool calls
- `bootstrapResultBytes` (int, pre-EVAL-04): bootstrap result size
- `bootstrapDurationMillis` (int, pre-EVAL-04): bootstrap phase duration
- `modelRequestsBeforeFirstEvidence` (int, pre-EVAL-04): model requests until first evidence
- `modelRequestCount` (int, pre-EVAL-04): provider calls incl. retries
- `logicalModelRequestCount` (int, pre-EVAL-04): logical model calls, retries excluded
- `planStepsCompleted` (int, pre-EVAL-04): declared plan steps executed
- `planStepsTotal` (int, pre-EVAL-04): declared plan steps (0 = no plan)
- `runElapsedMillis` (int, pre-EVAL-04): wall time of the run

---

Regenerate: `node tools/agent_metrics/summarize.mjs --jsonl tools/agent_metrics/samples --format md --baseline` — and verify with `node tools/agent_metrics/summarize.mjs --check`.

#!/usr/bin/env node
/**
 * summarize.mjs — OPT-EVAL-04-02: aggregate Agent run metrics from the
 * on-device diagnostics JSONL written by `AgentDiagnosticsRecorder`
 * (app/src/main/java/com/example/layanalyzer/ai/audit/AgentDiagnosticsRecorder.kt).
 *
 * Usage (repo root, Node >= 18, no npm dependencies):
 *
 *   node tools/agent_metrics/summarize.mjs --jsonl <path> [--format md|json] [--out <file>]
 *   node tools/agent_metrics/summarize.mjs --check
 *   node tools/agent_metrics/summarize.mjs --emit-samples <dir>
 *
 *   --jsonl <path>   Diagnostics source: a directory containing *.jsonl files
 *                    (the recorder's `agent_logs/` dir: active
 *                    `agent-diagnostics.jsonl` plus rotated
 *                    `agent-diagnostics-<ts>.jsonl`), or a single .jsonl file.
 *   --format md|json Output format (default md).
 *   --out <file>     Also write the report to this file (stdout still prints).
 *   --baseline       Mark the report as the archived OPT-EVAL-04 baseline
 *                    (adds the provenance banner; used for v1 + --check).
 *   --check          Self-check: parse/aggregate the synthetic fixture below
 *                    and assert the hand-computable numbers, verify that
 *                    `samples/` matches the embedded fixture, and that the
 *                    archived baseline report regenerates byte-identically.
 *                    Exits non-zero on any failure.
 *   --emit-samples   Write the embedded synthetic JSONL fixture into <dir>
 *                    (how `tools/agent_metrics/samples/` was produced).
 *
 * Input format (schemaVersion 2, per AgentDiagnosticsRecorder.encode):
 * one JSON object per line; `schema` is "AgentDiagnosticsEvent" (streaming
 * events) or "AgentDiagnosticsRun" (legacy whole-run record; skipped here).
 * Event lines carry runId/sessionId/sequence/timestampMillis/eventType/status/
 * attributes/failure.  Attribute values arrive as strings
 * (e.g. "citationRejectionRate":"0.5000"); the parser also accepts JSON
 * numbers so a future encoder change is non-breaking.
 *
 * Privacy contract: the input already contains only stable ids, counts and reason codes.
 * This script additionally never echoes runId/sessionId/conversationId text
 * into the report — runs are identified by a truncated SHA-256 hash only —
 * and never reads free-text fields (failure messages, modelId, ...).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// METRICS REGISTRY — the OPT-EVAL-04 registration contract (gate §9.1-1).
//
// CONVENTION: every future behaviour task that adds attributes to the
// RunMetrics diagnostics event MUST register its fields here, in the same
// change that emits them, so the baseline aggregate never silently ignores a
// new P0 signal.  Kinds:
//   'rate'      number in [0,1]           -> mean / median / max over runs
//   'flag'      0/1 or true/false          -> triggered x/n (percent)
//   'histogram' "Label:n,Label:n,..."      -> merged per-label counts
//   'int'       count / millis / bytes     -> mean (+ sum / min / max)
// Only register fields that are REALLY emitted today.  A registered field
// that is absent from a run's event (grey-release / pre-upgrade data) is
// reported as `missing` and excluded from that metric's denominator — the
// script never fails on unknown-old data and never fabricates values.
//
// Planned fields named by the task doc — NOT emitted yet, do not add them
// until the producing task lands, then register them here:
//   OPT-VAL-03-01                   : alignmentFailures (rate)
//   OPT-COG-03-04                   : criticStatus = skipped|failed|ran
//                                     (new kind: categorical)
//   OPT-COG-06-03                   : effort bucketing (Quick/Full split of
//                                     the existing means — a grouping key,
//                                     not a metric)
// Landed: OPT-VAL-04-03 registers negativePolarityDeclared /
// negativePolarityConflict below (both int counts; the conflict rate is a
// derived figure between them, mirroring the plan-step completion rate).
// OPT-VAL-01-02 registers planCoverageGaps below (int count of playbook
// checks still uncovered at report acceptance).
// OPT-VAL-02-03 registers signalCoverageGaps below (int count of
// host-enumerated baseline signals still unaddressed at report acceptance).
// ---------------------------------------------------------------------------

const METRICS = {
  // --- OPT-EVAL-04-01 run-quality metrics (AgentLoop.runQualityAttributes) ---
  citationRejectionRate: {
    kind: 'rate',
    source: 'OPT-EVAL-04-01',
    label: 'citationRejectionRate',
    note: 'rejected / submitted citations across all validation rounds of the run; 0 when nothing was submitted',
  },
  revisionTriggered: {
    kind: 'flag',
    source: 'OPT-EVAL-04-01',
    label: 'revisionTriggered',
    note: 'validator rejections ever bought a revision turn',
  },
  confidenceDistribution: {
    kind: 'histogram',
    source: 'OPT-EVAL-04-01',
    label: 'confidenceDistribution',
    buckets: ['High', 'Medium', 'Low', 'Unknown'], // AgentLoop.CONFIDENCE_HISTOGRAM_ORDER
    note: 'findings per confidence level in the final (or most recent) validated report',
  },
  // --- OPT-VAL-04-03 polarity double-track (AgentLoop.runQualityAttributes) ---
  negativePolarityDeclared: {
    kind: 'int',
    source: 'OPT-VAL-04-03',
    unit: 'findings',
    label: 'negativePolarityDeclared',
    note: 'findings that declared polarity=Negative, summed across the run\'s validation rounds',
  },
  negativePolarityConflict: {
    kind: 'int',
    source: 'OPT-VAL-04-03',
    unit: 'rejections',
    label: 'negativePolarityConflict',
    note: 'polarity_claim_conflict rejections raised when a Positive/Neutral declaration met an absence-claiming observation, summed across rounds',
  },
  // --- OPT-VAL-01-02 playbook check coverage (AgentLoop.runQualityAttributes) ---
  planCoverageGaps: {
    kind: 'int',
    source: 'OPT-VAL-01-02',
    unit: 'checks',
    label: 'planCoverageGaps',
    note: 'playbook checks still uncovered when the run\'s report was accepted (incl. the unattributable degrade-to-limitation path); 0 on gated runs without gaps and on valve-off runs',
  },
  // --- OPT-VAL-02-03 baseline signal coverage (AgentLoop.runQualityAttributes) ---
  signalCoverageGaps: {
    kind: 'int',
    source: 'OPT-VAL-02-03',
    unit: 'signals',
    label: 'signalCoverageGaps',
    note: 'host-enumerated baseline signals still unaddressed when the run\'s report was accepted (incl. the limitations-only degradation path); 0 when the rule did not run (valve off, no signals enumerated, or no submit accepted)',
  },
  // --- pre-existing RunMetrics attributes (AgentLoop.diagnosticAttributes) ---
  historyCompactedAtEntry: {
    kind: 'flag',
    source: 'pre-EVAL-04',
    label: 'historyCompactedAtEntry',
    note: 'replayed history was compacted before the first model call',
  },
  bootstrapToolCount: { kind: 'int', source: 'pre-EVAL-04', unit: 'calls', label: 'bootstrapToolCount', note: 'bootstrap tool calls' },
  bootstrapResultBytes: { kind: 'int', source: 'pre-EVAL-04', unit: 'bytes', label: 'bootstrapResultBytes', note: 'bootstrap result size' },
  bootstrapDurationMillis: { kind: 'int', source: 'pre-EVAL-04', unit: 'ms', label: 'bootstrapDurationMillis', note: 'bootstrap phase duration' },
  modelRequestsBeforeFirstEvidence: { kind: 'int', source: 'pre-EVAL-04', unit: 'calls', label: 'modelRequestsBeforeFirstEvidence', note: 'model requests until first evidence' },
  modelRequestCount: { kind: 'int', source: 'pre-EVAL-04', unit: 'calls', label: 'modelRequestCount', note: 'provider calls incl. retries' },
  logicalModelRequestCount: { kind: 'int', source: 'pre-EVAL-04', unit: 'calls', label: 'logicalModelRequestCount', note: 'logical model calls, retries excluded' },
  planStepsCompleted: { kind: 'int', source: 'pre-EVAL-04', unit: 'steps', label: 'planStepsCompleted', note: 'declared plan steps executed' },
  planStepsTotal: { kind: 'int', source: 'pre-EVAL-04', unit: 'steps', label: 'planStepsTotal', note: 'declared plan steps (0 = no plan)' },
  runElapsedMillis: { kind: 'int', source: 'pre-EVAL-04', unit: 'ms', label: 'runElapsedMillis', note: 'wall time of the run' },
};

// ---------------------------------------------------------------------------
// argument parsing
// ---------------------------------------------------------------------------

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const BASELINE_REL = 'baseline/synthetic_expected.json';
const SAMPLES_REL = 'samples';
/** Canonical label the archived baseline was generated with (stable bytes). */
const BASELINE_INPUT_LABEL = 'tools/agent_metrics/samples';
const BASELINE_COMMAND =
  'node tools/agent_metrics/summarize.mjs --jsonl tools/agent_metrics/samples --format md --baseline';

const args = process.argv.slice(2);

function failUsage(message) {
  console.error(`summarize.mjs: ${message}\nRun with --help for usage.`);
  process.exit(2);
}

const opts = {
  jsonl: null,
  format: 'md',
  out: null,
  check: false,
  baseline: false,
  emitSamples: null,
};

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  switch (arg) {
    case '--jsonl':
      i += 1;
      if (i >= args.length) failUsage('--jsonl needs a path');
      opts.jsonl = args[i];
      break;
    case '--format':
      i += 1;
      if (i >= args.length) failUsage('--format needs md or json');
      opts.format = args[i];
      break;
    case '--out':
      i += 1;
      if (i >= args.length) failUsage('--out needs a file path');
      opts.out = args[i];
      break;
    case '--check':
      opts.check = true;
      break;
    case '--baseline':
      opts.baseline = true;
      break;
    case '--emit-samples':
      i += 1;
      if (i >= args.length) failUsage('--emit-samples needs a directory');
      opts.emitSamples = args[i];
      break;
    case '-h':
    case '--help':
      printHelp();
      process.exit(0);
      break;
    default:
      failUsage(`unknown argument ${arg}`);
  }
}

if (!['md', 'json'].includes(opts.format)) failUsage(`unknown --format ${opts.format}`);

function printHelp() {
  const usage = [
    'usage: node tools/agent_metrics/summarize.mjs --jsonl <dir|file.jsonl> [--format md|json] [--out <file>] [--baseline]',
    '       node tools/agent_metrics/summarize.mjs --check',
    '       node tools/agent_metrics/summarize.mjs --emit-samples <dir>',
    '',
    'Aggregates RunMetrics events from the Agent diagnostics JSONL logs',
    '(filesDir/agent_logs/ on device). See the header comment of this file',
    'and CONTRIBUTING.md for the metric registration contract.',
  ];
  console.log(usage.join('\n'));
}

// ---------------------------------------------------------------------------
// tolerant attribute coercion
// ---------------------------------------------------------------------------

/** Number from a JSON number or a numeric string; null otherwise. */
function asNumber(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/** 0/1 from "1"/"0"/1/0/true/false/"true"/"false"; null otherwise. */
function asFlag(value) {
  if (typeof value === 'boolean') return value ? 1 : 0;
  const numeric = asNumber(value);
  if (numeric !== null) return numeric > 0 ? 1 : 0;
  if (typeof value === 'string') {
    const lower = value.trim().toLowerCase();
    if (lower === 'true') return 1;
    if (lower === 'false') return 0;
  }
  return null;
}

/**
 * Histogram from "High:0,Medium:1,Low:0,Unknown:0" (or an object).  Parses by
 * label so segment order is not load-bearing; unknown labels are kept under
 * `other`; a value with no parseable segment counts as missing.
 */
function asHistogram(value, knownBuckets) {
  const counts = new Map();
  let parsed = 0;
  const add = (label, numeric) => {
    if (typeof label !== 'string' || numeric === null) return;
    counts.set(label.trim(), (counts.get(label.trim()) ?? 0) + numeric);
    parsed += 1;
  };
  if (typeof value === 'string') {
    for (const segment of value.split(',')) {
      const colon = segment.lastIndexOf(':');
      if (colon <= 0) continue;
      add(segment.slice(0, colon), asNumber(segment.slice(colon + 1)));
    }
  } else if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [label, raw] of Object.entries(value)) add(label, asNumber(raw));
  }
  if (parsed === 0) return null;
  const buckets = {};
  let other = {};
  for (const [label, count] of counts) {
    if (knownBuckets.includes(label)) buckets[label] = count;
    else other[label] = count;
  }
  return { buckets, other, total: [...counts.values()].reduce((a, b) => a + b, 0) };
}

function hashRunId(runId) {
  return crypto.createHash('sha256').update(String(runId)).digest('hex').slice(0, 10);
}

// ---------------------------------------------------------------------------
// parsing + aggregation
// ---------------------------------------------------------------------------

/**
 * @param files list of `{name, text}` — name used only for stats/report.
 * @param inputLabel path or label as provided on the command line.
 */
function aggregate(files, inputLabel) {
  const stats = {
    files: files.map((file) => file.name),
    totalLines: 0,
    blankLines: 0,
    malformedLines: 0,
    runSchemaLines: 0, // whole-run records (schemaVersion-era "AgentDiagnosticsRun")
    skippedOtherSchema: 0, // e.g. export envelopes, non-objects
    eventsWithoutRunId: 0,
    unexpectedSchemaVersions: {},
  };
  /** runId -> {runId, status, metricsEvent|null, metricsSequence} */
  const runs = new Map();
  const dup = { duplicateRunMetricsEvents: 0 };

  for (const file of files) {
    for (const line of file.text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) {
        stats.blankLines += 1;
        continue;
      }
      stats.totalLines += 1;
      let entry;
      try {
        entry = JSON.parse(trimmed);
      } catch {
        stats.malformedLines += 1; // torn tail after process death, etc.
        continue;
      }
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        stats.skippedOtherSchema += 1;
        continue;
      }
      if (entry.schema === 'AgentDiagnosticsRun') {
        stats.runSchemaLines += 1;
        continue;
      }
      if (entry.schema !== 'AgentDiagnosticsEvent') {
        stats.skippedOtherSchema += 1;
        continue;
      }
      const version = typeof entry.schemaVersion === 'number' ? String(entry.schemaVersion) : 'none';
      if (version !== '2') {
        stats.unexpectedSchemaVersions[version] = (stats.unexpectedSchemaVersions[version] ?? 0) + 1;
      }
      if (typeof entry.runId !== 'string' || entry.runId.trim() === '') {
        stats.eventsWithoutRunId += 1;
        continue;
      }
      let record = runs.get(entry.runId);
      if (!record) {
        record = { runId: entry.runId, status: null, metricsEvent: null, metricsSequence: -1 };
        runs.set(entry.runId, record);
      }
      if (entry.eventType === 'RunFinished' || entry.eventType === 'RunAbandoned') {
        if (typeof entry.status === 'string' && entry.status.trim() !== '') record.status = entry.status;
        else if (entry.eventType === 'RunAbandoned') record.status = 'abandoned';
      } else if (entry.eventType === 'RunMetrics') {
        const sequence = asNumber(entry.sequence) ?? 0;
        if (record.metricsEvent) {
          dup.duplicateRunMetricsEvents += 1;
          if (sequence < record.metricsSequence) continue; // keep the latest
        }
        record.metricsEvent = entry;
        record.metricsSequence = sequence;
      }
    }
  }

  // ----- per-run extraction -------------------------------------------------
  const qualityFields = Object.keys(METRICS).filter(
    (field) => METRICS[field].source === 'OPT-EVAL-04-01',
  );
  const perRun = [];
  const agg = {}; // field -> {kind, values/flags/hist, n, missing, invalid}
  for (const field of Object.keys(METRICS)) {
    const kind = METRICS[field].kind;
    agg[field] = {
      field,
      kind,
      source: METRICS[field].source,
      note: METRICS[field].note,
      unit: METRICS[field].unit ?? null,
      reported: 0,
      missing: 0,
      invalid: 0,
      ...(kind === 'rate' ? { rates: [] } : {}),
      ...(kind === 'flag' ? { triggered: 0 } : {}),
      ...(kind === 'int' ? { values: [], sum: 0 } : {}),
      ...(kind === 'histogram' ? { merged: {}, mergedOther: {}, total: 0 } : {}),
    };
  }

  const runMetricsEvents = [...runs.values()].filter((record) => record.metricsEvent);
  let legacyRuns = 0;
  const terminalStatusCounts = {};

  for (const record of [...runs.values()].sort((a, b) => hashRunId(a.runId).localeCompare(hashRunId(b.runId)))) {
    if (!record.metricsEvent) continue;
    const attributes = (record.metricsEvent.attributes && typeof record.metricsEvent.attributes === 'object')
      ? record.metricsEvent.attributes
      : {};
    if (qualityFields.every((field) => attributes[field] === undefined)) legacyRuns += 1;
    const row = {
      runHash: hashRunId(record.runId),
      status: record.status ?? 'unfinished',
      values: {},
    };
    for (const field of Object.keys(METRICS)) {
      const spec = METRICS[field];
      const bucket = agg[field];
      const raw = attributes[field];
      let value = null;
      if (raw === undefined || raw === null) {
        bucket.missing += 1;
      } else if (spec.kind === 'rate') {
        value = asNumber(raw);
        if (value === null || value < 0 || value > 1) {
          bucket.invalid += 1;
          value = null;
        } else {
          bucket.rates.push(value);
        }
      } else if (spec.kind === 'flag') {
        value = asFlag(raw);
        if (value === null) bucket.invalid += 1;
        else bucket.triggered += value;
      } else if (spec.kind === 'int') {
        value = asNumber(raw);
        if (value === null) bucket.invalid += 1;
        else {
          bucket.values.push(value);
          bucket.sum += value;
        }
      } else if (spec.kind === 'histogram') {
        value = asHistogram(raw, spec.buckets);
        if (value === null) bucket.invalid += 1;
        else {
          for (const [label, count] of Object.entries(value.buckets)) {
            bucket.merged[label] = (bucket.merged[label] ?? 0) + count;
          }
          for (const [label, count] of Object.entries(value.other)) {
            bucket.mergedOther[label] = (bucket.mergedOther[label] ?? 0) + count;
          }
          bucket.total += value.total;
        }
      }
      if (value !== null) bucket.reported += 1;
      // `raw` stays for JSON debugging; `parsed` drives the tables.
      row.values[field] = { raw, parsed: value };
    }
    perRun.push(row);
  }

  for (const record of runs.values()) {
    if (record.status) {
      terminalStatusCounts[record.status] = (terminalStatusCounts[record.status] ?? 0) + 1;
    }
  }

  // ----- finalize metric summaries -----------------------------------------
  const metrics = {};
  for (const field of Object.keys(METRICS)) {
    const spec = METRICS[field];
    const bucket = agg[field];
    const summary = {
      kind: spec.kind,
      source: spec.source,
      note: spec.note,
      unit: bucket.unit,
      reported: bucket.reported,
      missing: bucket.missing,
      invalid: bucket.invalid,
    };
    const sorted = [...(bucket.rates ?? bucket.values ?? [])].sort((a, b) => a - b);
    if (spec.kind === 'rate' || spec.kind === 'int') {
      const n = sorted.length;
      summary.count = n;
      summary.mean = n ? sorted.reduce((a, b) => a + b, 0) / n : null;
      summary.min = n ? sorted[0] : null;
      summary.max = n ? sorted[n - 1] : null;
      summary.sum = spec.kind === 'int' && n ? bucket.sum : undefined;
      if (spec.kind === 'rate' && n) {
        summary.median = n % 2 ? sorted[(n - 1) / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
      }
    } else if (spec.kind === 'flag') {
      summary.triggered = bucket.triggered;
      summary.rate = bucket.reported ? bucket.triggered / bucket.reported : null;
    } else if (spec.kind === 'histogram') {
      summary.buckets = spec.buckets.reduce((acc, label) => {
        acc[label] = bucket.merged[label] ?? 0;
        return acc;
      }, {});
      if (Object.keys(bucket.mergedOther).length) summary.other = bucket.mergedOther;
      summary.total = bucket.total;
    }
    metrics[field] = summary;
  }

  // Derived: plan-step completion over all runs reporting both fields.
  let planDone = 0;
  let planTotal = 0;
  // Derived: polarity-conflict rate (OPT-VAL-04-03) over all runs reporting
  // the fields — conflict rejections / declared-negative findings.  A missing
  // field (pre-upgrade run) is skipped, never counted as zero in the rate.
  let polarityDeclared = 0;
  let polarityConflict = 0;
  for (const record of runMetricsEvents) {
    const attributes = record.metricsEvent.attributes ?? {};
    const completed = asNumber(attributes.planStepsCompleted);
    const total = asNumber(attributes.planStepsTotal);
    if (completed !== null) planDone += completed;
    if (total !== null) planTotal += total;
    const declared = asNumber(attributes.negativePolarityDeclared);
    const conflict = asNumber(attributes.negativePolarityConflict);
    if (declared !== null) polarityDeclared += declared;
    if (conflict !== null) polarityConflict += conflict;
  }
  const derived = {
    planStepCompletionRate: {
      completed: planDone,
      declared: planTotal,
      rate: planTotal > 0 ? planDone / planTotal : null,
    },
    polarityConflictRate: {
      conflict: polarityConflict,
      declared: polarityDeclared,
      rate: polarityDeclared > 0 ? polarityConflict / polarityDeclared : null,
    },
  };

  return {
    schema: 'agent-metrics-summary',
    schemaVersion: 1,
    input: inputLabel,
    parse: stats,
    runs: {
      distinctRunIds: runs.size,
      withRunMetrics: runMetricsEvents.length,
      legacyWithoutQualityAttributes: legacyRuns,
      duplicateRunMetricsEvents: dup.duplicateRunMetricsEvents,
      terminalStatusCounts,
    },
    metrics,
    derived,
    perRun,
  };
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

const fmt = {
  rate: (x) => (x === null || x === undefined ? '—' : x.toFixed(4)),
  percent: (x) => (x === null || x === undefined ? '—' : `${(x * 100).toFixed(2)}%`),
  mean: (x) => {
    if (x === null || x === undefined) return '—';
    return Math.abs(x - Math.round(x)) < 1e-9 ? String(Math.round(x)) : x.toFixed(2);
  },
  int: (x) => (x === null || x === undefined ? '—' : String(Math.round(x))),
};

function valueColumn(result, field) {
  const spec = METRICS[field];
  const m = result.metrics[field];
  if (!m) return '—';
  if (m.reported === 0 && m.invalid === 0) return 'n/a (no run reports it)';
  switch (spec.kind) {
    case 'rate':
      return m.count
        ? `mean ${fmt.rate(m.mean)} · median ${fmt.rate(m.median)} · max ${fmt.rate(m.max)}`
        : 'n/a';
    case 'flag':
      return `${m.triggered}/${m.reported} (${fmt.percent(m.rate)})`;
    case 'int':
      return m.count ? `mean ${fmt.mean(m.mean)} · sum ${fmt.int(m.sum)} · min ${fmt.int(m.min)} · max ${fmt.int(m.max)}` : 'n/a';
    case 'histogram': {
      const parts = spec.buckets.map((label) => `${label} ${m.buckets[label] ?? 0}`);
      if (m.other) parts.push(...Object.entries(m.other).map(([label, count]) => `${label} ${count}`));
      return `${parts.join(' · ')} (total ${m.total} findings)`;
    }
    default:
      return '—';
  }
}

function renderMd(result, baseline) {
  const lines = [];
  const title = baseline
    ? '# Agent run-metrics baseline v1 (synthetic fixtures — OPT-EVAL-04-02)'
    : '# Agent run-metrics summary';
  lines.push(title, '');
  if (baseline) {
    lines.push(
      '> **数据来源 / data source**: every aggregated row comes from the **synthetic**',
      '> JVM-mock-run fixture under `tools/agent_metrics/samples/` (hand-written JSONL,',
      '> modelled on the two OPT-EVAL-04-01 `AgentLoopTest` RunMetrics cases).',
      '> **这不是真机基线 / this is NOT a real-device baseline.** The device baseline is',
      '> produced after pulling `agent_logs/` from a device and re-running the exact',
      '> same command (see `CONTRIBUTING.md`).',
      '',
    );
  }
  lines.push(
    `- Input: \`${result.input}\` (${result.parse.files.length} jsonl file${result.parse.files.length === 1 ? '' : 's'}: ${result.parse.files.join(', ')})`,
    `- Lines: ${result.parse.totalLines} parsed, ${result.parse.malformedLines} malformed (skipped), ` +
      `${result.parse.blankLines} blank, ${result.parse.runSchemaLines} run-record lines and ${result.parse.skippedOtherSchema} other-schema lines skipped, ` +
      `${result.parse.eventsWithoutRunId} events without runId ignored`,
    `- Runs: ${result.runs.distinctRunIds} distinct runIds in event lines, ${result.runs.withRunMetrics} with a RunMetrics event` +
      `${result.runs.duplicateRunMetricsEvents ? `, ${result.runs.duplicateRunMetricsEvents} duplicate RunMetrics collapsed (latest sequence kept)` : ''}` +
      `${result.runs.legacyWithoutQualityAttributes ? `; ${result.runs.legacyWithoutQualityAttributes} run(s) predate the OPT-EVAL-04-01 fields and are excluded from those denominators` : ''}`,
    `- Terminal run status: ${Object.entries(result.runs.terminalStatusCounts).map(([status, count]) => `${status} ${count}`).join(' · ') || 'none observed'}`,
    '',
    '## Quality metrics',
    '',
    '| metric | source | runs reporting | value |',
    '|---|---|---|---|',
  );
  for (const field of Object.keys(METRICS).filter((name) => METRICS[name].source === 'OPT-EVAL-04-01' || name === 'historyCompactedAtEntry')) {
    const m = result.metrics[field];
    lines.push(
      `| \`${field}\` | ${m.source} | ${m.reported}/${result.runs.withRunMetrics}${m.missing ? ` (${m.missing} missing)` : ''}${m.invalid ? ` (${m.invalid} invalid)` : ''} | ${valueColumn(result, field)} |`,
    );
  }
  lines.push(
    '',
    '## Existing run metrics (per-run means)',
    '',
    '| metric | unit | runs reporting | mean | sum | min | max |',
    '|---|---|---|---:|---:|---:|---:|',
  );
  for (const field of Object.keys(METRICS).filter((name) => METRICS[name].kind === 'int' && METRICS[name].source !== 'OPT-EVAL-04-01')) {
    const m = result.metrics[field];
    lines.push(
      `| \`${field}\` | ${m.unit ?? ''} | ${m.reported}/${result.runs.withRunMetrics}${m.missing ? ` (${m.missing} missing)` : ''} | ${fmt.mean(m.mean)} | ${fmt.int(m.sum)} | ${fmt.int(m.min)} | ${fmt.int(m.max)} |`,
    );
  }
  const plan = result.derived.planStepCompletionRate;
  const polarity = result.derived.polarityConflictRate;
  lines.push(
    '',
    `Derived **plan step completion rate**: \`${fmt.int(plan.completed)}\` completed of \`${fmt.int(plan.declared)}\` declared plan steps` +
      (plan.rate === null ? ' (no plan declared).' : ` = **${fmt.percent(plan.rate)}**.`),
    '',
    `Derived **polarity conflict rate** (OPT-VAL-04-03): \`${fmt.int(polarity.conflict)}\` \`polarity_claim_conflict\` rejections over \`${fmt.int(polarity.declared)}\` declared-negative findings` +
      (polarity.rate === null ? ' (no negative finding declared).' : ` = **${fmt.percent(polarity.rate)}**.`),
    '',
    '## Per-run detail',
    '',
    'runId is replaced by a truncated SHA-256 hash (privacy red line: no raw ids in reports).',
    '',
    '| run | status | citationRejectionRate | revisionTriggered | H/M/L/U findings | modelReq (logical) | plan steps | elapsed ms |',
    '|---|---|---|---|---|---|---|---:|',
  );
  const cell = {
    rate: (entry) => (entry.parsed === null ? '—' : fmt.rate(entry.parsed)),
    flag: (entry) => (entry.parsed === null ? '—' : (entry.parsed ? 'yes' : 'no')),
    hist: (entry) => (entry.parsed === null
      ? '—'
      : `${entry.parsed.buckets.High ?? 0}/${entry.parsed.buckets.Medium ?? 0}/`
        + `${entry.parsed.buckets.Low ?? 0}/${entry.parsed.buckets.Unknown ?? 0}`),
    int: (entry) => (entry.parsed === null ? '—' : fmt.int(entry.parsed)),
  };
  for (const row of result.perRun) {
    const v = row.values;
    lines.push(
      `| \`${row.runHash}\` | ${row.status} | `
      + `${cell.rate(v.citationRejectionRate)} | `
      + `${cell.flag(v.revisionTriggered)} | `
      + `${cell.hist(v.confidenceDistribution)} | `
      + `${cell.int(v.modelRequestCount)} (${cell.int(v.logicalModelRequestCount)}) | `
      + `${cell.int(v.planStepsCompleted)}/${cell.int(v.planStepsTotal)} | `
      + `${cell.int(v.runElapsedMillis)} |`,
    );
  }
  lines.push(
    '',
    '## Definitions',
    '',
  );
  for (const field of Object.keys(METRICS)) {
    lines.push(`- \`${field}\` (${METRICS[field].kind}, ${METRICS[field].source}): ${METRICS[field].note}`);
  }
  lines.push(
    '',
    '---',
    '',
    baseline
      ? `Regenerate: \`${BASELINE_COMMAND}\` — and verify with \`node tools/agent_metrics/summarize.mjs --check\`.`
      : `Generated by \`node tools/agent_metrics/summarize.mjs --jsonl <path>\`. New behaviour tasks must register their RunMetrics fields in the METRICS registry at the top of that script (see CONTRIBUTING.md).`,
    '',
  );
  return lines.join('\n');
}

function renderJson(result, baseline) {
  const payload = baseline ? { ...result, provenance: { synthetic: true, note: 'JVM mock-run synthetic fixtures; not a real-device baseline' } } : result;
  return `${JSON.stringify(payload, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// embedded synthetic fixtures (the ONLY data behind the v1 baseline)
// ---------------------------------------------------------------------------

function event(partial) {
  return {
    schema: 'AgentDiagnosticsEvent',
    schemaVersion: 2,
    sessionId: partial.runId.replace(/-[^-]*$/, ''),
    captureRef: 'synth001',
    modelId: 'synthetic-model',
    promptVersion: 'prompt-7',
    playbookVersion: null,
    phase: null,
    turn: null,
    step: null,
    toolName: null,
    argumentsHash: null,
    durationMillis: null,
    failure: null,
    conversationId: null,
    ...partial,
  };
}

const SAMPLE_FILES = {
  // Active log: runs A/B/C/E, mirroring the OPT-EVAL-04-01 AgentLoopTest
  // cases (A: 2 rejected of 4 submitted citations + revision + merged
  // Medium:1 finding; B: clean run High:1) plus two extra synthetic shapes
  // (C mid-range; E with JSON-number-typed attributes, parse tolerance).
  'agent-diagnostics.jsonl': [
    event({ runId: 'synth-run-A', sequence: 1, timestampMillis: 1757000000001, eventType: 'RunStarted', status: 'started', attributes: { startedAtMillis: '1757000000000' } }),
    event({ runId: 'synth-run-A', sequence: 2, timestampMillis: 1757000184001, eventType: 'RunFinished', status: 'completed', phase: 'Completed', attributes: {} }),
    event({
      runId: 'synth-run-A', sequence: 3, timestampMillis: 1757000184002, eventType: 'RunMetrics', status: 'recorded', phase: 'Completed',
      attributes: {
        bootstrapToolCount: '1', bootstrapResultBytes: '1490', bootstrapDurationMillis: '1200',
        modelRequestsBeforeFirstEvidence: '2', modelRequestCount: '4', logicalModelRequestCount: '3',
        planStepsCompleted: '2', planStepsTotal: '2', runElapsedMillis: '184000', historyCompactedAtEntry: 'false',
        citationRejectionRate: '0.5000', revisionTriggered: '1', confidenceDistribution: 'High:0,Medium:1,Low:0,Unknown:0',
        negativePolarityDeclared: '2', negativePolarityConflict: '1', planCoverageGaps: '1', signalCoverageGaps: '2',
      },
    }),
    event({ runId: 'synth-run-B', sequence: 1, timestampMillis: 1757000300001, eventType: 'RunStarted', status: 'started', attributes: { startedAtMillis: '1757000300000' } }),
    event({ runId: 'synth-run-B', sequence: 2, timestampMillis: 1757000420001, eventType: 'RunFinished', status: 'completed', phase: 'Completed', attributes: {} }),
    event({
      runId: 'synth-run-B', sequence: 3, timestampMillis: 1757000420002, eventType: 'RunMetrics', status: 'recorded', phase: 'Completed',
      attributes: {
        bootstrapToolCount: '2', bootstrapResultBytes: '2200', bootstrapDurationMillis: '900',
        modelRequestsBeforeFirstEvidence: '1', modelRequestCount: '3', logicalModelRequestCount: '3',
        planStepsCompleted: '0', planStepsTotal: '0', runElapsedMillis: '120000', historyCompactedAtEntry: 'false',
        citationRejectionRate: '0.0000', revisionTriggered: '0', confidenceDistribution: 'High:1,Medium:0,Low:0,Unknown:0',
        negativePolarityDeclared: '1', negativePolarityConflict: '0', planCoverageGaps: '2', signalCoverageGaps: '0',
      },
    }),
    event({ runId: 'synth-run-C', sequence: 1, timestampMillis: 1757000500001, eventType: 'RunStarted', status: 'started', attributes: { startedAtMillis: '1757000500000' } }),
    event({ runId: 'synth-run-C', sequence: 2, timestampMillis: 1757000740001, eventType: 'RunFinished', status: 'completed', phase: 'Completed', attributes: {} }),
    event({
      runId: 'synth-run-C', sequence: 3, timestampMillis: 1757000740002, eventType: 'RunMetrics', status: 'recorded', phase: 'Completed',
      attributes: {
        bootstrapToolCount: '1', bootstrapResultBytes: '1024', bootstrapDurationMillis: '700',
        modelRequestsBeforeFirstEvidence: '2', modelRequestCount: '5', logicalModelRequestCount: '4',
        planStepsCompleted: '3', planStepsTotal: '4', runElapsedMillis: '240000', historyCompactedAtEntry: 'false',
        citationRejectionRate: '0.2500', revisionTriggered: '1', confidenceDistribution: 'High:2,Medium:1,Low:1,Unknown:0',
        negativePolarityDeclared: '3', negativePolarityConflict: '1', planCoverageGaps: '0', signalCoverageGaps: '1',
      },
    }),
    // Run E: numeric-typed quality attributes (parser must accept both the
    // current string form and a future true-JSON-number encoder).
    event({ runId: 'synth-run-E', sequence: 1, timestampMillis: 1757000800001, eventType: 'RunStarted', status: 'started', attributes: { startedAtMillis: '1757000800000' } }),
    event({ runId: 'synth-run-E', sequence: 2, timestampMillis: 1757000890001, eventType: 'RunFinished', status: 'completed', phase: 'Completed', attributes: {} }),
    event({
      runId: 'synth-run-E', sequence: 3, timestampMillis: 1757000890002, eventType: 'RunMetrics', status: 'recorded', phase: 'Completed',
      attributes: {
        bootstrapToolCount: '3', bootstrapResultBytes: '3072', bootstrapDurationMillis: '1500',
        modelRequestsBeforeFirstEvidence: '1', modelRequestCount: '4', logicalModelRequestCount: '4',
        planStepsCompleted: '1', planStepsTotal: '1', runElapsedMillis: '90000', historyCompactedAtEntry: 'false',
        citationRejectionRate: 0.125, revisionTriggered: 0, confidenceDistribution: 'High:1,Medium:2,Low:0,Unknown:1',
        negativePolarityDeclared: 2, negativePolarityConflict: 0, planCoverageGaps: 1, signalCoverageGaps: 0,
      },
    }),
  ],
  // Rotated log with one pre-OPT-EVAL-04-01 run (D): RunMetrics without the
  // quality attributes — must land in the "missing" bucket, not error out.
  'agent-diagnostics-1757000000000.jsonl': [
    event({ runId: 'synth-run-D', sequence: 1, timestampMillis: 1756900000001, eventType: 'RunStarted', status: 'started', attributes: { startedAtMillis: '1756900000000' } }),
    event({ runId: 'synth-run-D', sequence: 2, timestampMillis: 1756900300001, eventType: 'RunFinished', status: 'failed', phase: 'Failed', attributes: {} }),
    event({
      runId: 'synth-run-D', sequence: 3, timestampMillis: 1756900300002, eventType: 'RunMetrics', status: 'recorded', phase: 'Failed',
      attributes: {
        bootstrapToolCount: '2', bootstrapResultBytes: '2048', bootstrapDurationMillis: '800',
        modelRequestsBeforeFirstEvidence: '1', modelRequestCount: '6', logicalModelRequestCount: '5',
        planStepsCompleted: '1', planStepsTotal: '3', runElapsedMillis: '300000', historyCompactedAtEntry: 'true',
      },
    }),
  ],
};

function serializeSampleFiles() {
  const map = new Map();
  for (const [name, events] of Object.entries(SAMPLE_FILES)) {
    map.set(name, `${events.map((entry) => JSON.stringify(entry)).join('\n')}\n`);
  }
  return map;
}

// ---------------------------------------------------------------------------
// --check
// ---------------------------------------------------------------------------

function runCheck() {
  const failures = [];
  const near = (actual, expected, label) => {
    if (actual === null || Math.abs(actual - expected) > 1e-9) {
      failures.push(`${label}: expected ${expected}, got ${actual}`);
    }
  };
  const eq = (actual, expected, label) => {
    if (actual !== expected) failures.push(`${label}: expected ${expected}, got ${actual}`);
  };

  // 1) parse + aggregate the embedded fixture plus deliberately hostile lines
  //    (malformed JSON, non-event schema, schema-less JSON, event without
  //    runId, and a duplicate RunMetrics with a later sequence).
  const serialized = serializeSampleFiles();
  const files = [...serialized.entries()].map(([name, text]) => ({ name, text }));
  files.push({
    name: 'check-junk.jsonl',
    text: [
      'this line is not json {{{',
      '{"schema":"AgentDiagnosticsRun","schemaVersion":2,"sessionId":"synth-run-X"}',
      '{"schema":"AgentDiagnosticsExport","runs":[],"events":[]}',
      '{"runId":"no-schema-here","eventType":"RunMetrics"}',
      '{"schema":"AgentDiagnosticsEvent","schemaVersion":2,"eventType":"RunMetrics","attributes":{}}',
      JSON.stringify(event({
        runId: 'synth-run-A', sequence: 4, timestampMillis: 1757000184003, eventType: 'RunMetrics', status: 'recorded', phase: 'Completed',
        attributes: {
          bootstrapToolCount: '1', bootstrapResultBytes: '1490', bootstrapDurationMillis: '1200',
          modelRequestsBeforeFirstEvidence: '2', modelRequestCount: '4', logicalModelRequestCount: '3',
          planStepsCompleted: '2', planStepsTotal: '2', runElapsedMillis: '184000', historyCompactedAtEntry: 'false',
          citationRejectionRate: '0.7500', revisionTriggered: '1', confidenceDistribution: 'High:0,Medium:1,Low:0,Unknown:0',
          negativePolarityDeclared: '2', negativePolarityConflict: '1', planCoverageGaps: '1', signalCoverageGaps: '2',
        },
      })),
      '',
    ].join('\n'),
  });
  const check = aggregate(files, 'check:synthetic');

  eq(check.parse.malformedLines, 1, 'malformedLines');
  eq(check.parse.runSchemaLines, 1, 'runSchemaLines');
  eq(check.parse.skippedOtherSchema, 2, 'skippedOtherSchema');
  eq(check.parse.eventsWithoutRunId, 1, 'eventsWithoutRunId');
  eq(check.runs.distinctRunIds, 5, 'distinctRunIds');
  eq(check.runs.withRunMetrics, 5, 'withRunMetrics');
  eq(check.runs.duplicateRunMetricsEvents, 1, 'duplicateRunMetricsEvents');
  eq(check.runs.legacyWithoutQualityAttributes, 1, 'legacyWithoutQualityAttributes');
  eq(check.runs.terminalStatusCounts.completed, 4, 'status completed');
  eq(check.runs.terminalStatusCounts.failed, 1, 'status failed');

  // citationRejectionRate over A(latest wins = 0.75), B 0, C 0.25, E 0.125.
  const rate = check.metrics.citationRejectionRate;
  eq(rate.reported, 4, 'citation reported');
  eq(rate.missing, 1, 'citation missing (legacy run D)');
  near(rate.mean, (0.75 + 0 + 0.25 + 0.125) / 4, 'citation mean');
  near(rate.median, (0.125 + 0.25) / 2, 'citation median');
  near(rate.max, 0.75, 'citation max');
  const rev = check.metrics.revisionTriggered;
  eq(rev.reported, 4, 'revision reported');
  eq(rev.triggered, 2, 'revision triggered');
  near(rev.rate, 0.5, 'revision rate');
  const conf = check.metrics.confidenceDistribution;
  eq(conf.reported, 4, 'confidence reported');
  eq(JSON.stringify(conf.buckets), JSON.stringify({ High: 4, Medium: 4, Low: 1, Unknown: 1 }), 'confidence merged buckets');
  eq(conf.total, 10, 'confidence total findings');
  eq(check.metrics.historyCompactedAtEntry.triggered, 1, 'historyCompactedAtEntry triggered');
  eq(check.metrics.historyCompactedAtEntry.reported, 5, 'historyCompactedAtEntry reported');
  // modelRequestCount [4,3,5,4,6] over runs A,B,C,E,D.
  near(check.metrics.modelRequestCount.mean, (4 + 3 + 5 + 4 + 6) / 5, 'modelRequestCount mean');
  eq(check.metrics.modelRequestCount.reported, 5, 'modelRequestCount reported');
  near(check.derived.planStepCompletionRate.rate, 7 / 10, 'planStepCompletionRate');
  eq(check.derived.planStepCompletionRate.completed, 7, 'plan steps completed');
  eq(check.derived.planStepCompletionRate.declared, 10, 'plan steps declared');
  // OPT-VAL-04-03 polarity double-track.  Present on A(latest-wins, 2/1),
  // B(1/0), C(3/1), E(2/0); missing on the legacy run D.
  const declared = check.metrics.negativePolarityDeclared;
  eq(declared.reported, 4, 'negativePolarityDeclared reported');
  eq(declared.missing, 1, 'negativePolarityDeclared missing (legacy run D)');
  eq(declared.sum, 8, 'negativePolarityDeclared sum');
  near(declared.mean, 2, 'negativePolarityDeclared mean');
  const conflict = check.metrics.negativePolarityConflict;
  eq(conflict.reported, 4, 'negativePolarityConflict reported');
  eq(conflict.missing, 1, 'negativePolarityConflict missing (legacy run D)');
  eq(conflict.sum, 2, 'negativePolarityConflict sum');
  near(check.derived.polarityConflictRate.rate, 2 / 8, 'polarityConflictRate');
  eq(check.derived.polarityConflictRate.conflict, 2, 'polarity conflicts summed');
  eq(check.derived.polarityConflictRate.declared, 8, 'polarity declared summed');

  // OPT-VAL-01-02 playbook check coverage.  Present on A(latest-wins, 1),
  // B(2), C(0), E(1); missing on the legacy run D.
  const gaps = check.metrics.planCoverageGaps;
  eq(gaps.reported, 4, 'planCoverageGaps reported');
  eq(gaps.missing, 1, 'planCoverageGaps missing (legacy run D)');
  eq(gaps.sum, 4, 'planCoverageGaps sum');
  near(gaps.mean, 1, 'planCoverageGaps mean');
  eq(gaps.min, 0, 'planCoverageGaps min');
  eq(gaps.max, 2, 'planCoverageGaps max');

  // OPT-VAL-02-03 baseline signal coverage.  Present on A(latest-wins, 2),
  // B(0), C(1), E(0); missing on the legacy run D.
  const signalGaps = check.metrics.signalCoverageGaps;
  eq(signalGaps.reported, 4, 'signalCoverageGaps reported');
  eq(signalGaps.missing, 1, 'signalCoverageGaps missing (legacy run D)');
  eq(signalGaps.sum, 3, 'signalCoverageGaps sum');
  near(signalGaps.mean, 0.75, 'signalCoverageGaps mean');
  eq(signalGaps.min, 0, 'signalCoverageGaps min');
  eq(signalGaps.max, 2, 'signalCoverageGaps max');

  // 2) the committed samples/ dir must match the embedded fixture exactly.
  const samplesDir = path.join(SCRIPT_DIR, SAMPLES_REL);
  for (const [name, text] of serialized) {
    const file = path.join(samplesDir, name);
    if (!fs.existsSync(file)) failures.push(`MISSING  ${SAMPLES_REL}/${name}`);
    else if (fs.readFileSync(file, 'utf8') !== text) failures.push(`CHANGED  ${SAMPLES_REL}/${name}`);
  }

  // 3) the archived baseline report must regenerate byte-identically from
  //    samples/ (proves the archive matches its own inputs).
  const baselineFile = path.join(SCRIPT_DIR, BASELINE_REL);
  const diskFiles = fs.existsSync(samplesDir)
    ? fs.readdirSync(samplesDir).filter((name) => name.toLowerCase().endsWith('.jsonl')).sort()
        .map((name) => ({ name, text: fs.readFileSync(path.join(samplesDir, name), 'utf8') }))
    : [];
  if (!diskFiles.length) {
    failures.push(`MISSING  ${SAMPLES_REL}/*.jsonl`);
  } else {
    const report = renderJson(aggregate(diskFiles, BASELINE_INPUT_LABEL), true);
    if (!fs.existsSync(baselineFile)) failures.push(`MISSING  ${BASELINE_REL}`);
    else if (fs.readFileSync(baselineFile, 'utf8') !== report) failures.push(`CHANGED  ${BASELINE_REL} (regenerate with --out)`);
  }

  if (failures.length) {
    console.error(`summarize.mjs --check: ${failures.length} failure(s)`);
    failures.forEach((failure) => console.error(`  FAIL ${failure}`));
    process.exit(1);
  }
  console.log('summarize.mjs --check: all synthetic-sample parse/aggregate numbers, samples/ fixtures and the archived baseline report verified.');
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function collectInputFiles(target) {
  const resolved = path.resolve(target);
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch {
    failUsage(`--jsonl path not found: ${target}`);
  }
  let names = [];
  if (stat.isFile()) {
    names = [path.basename(resolved)];
    const dir = path.dirname(resolved);
    return [{ name: names[0], text: fs.readFileSync(path.join(dir, names[0]), 'utf8') }];
  }
  if (!stat.isDirectory()) failUsage(`--jsonl path is neither file nor directory: ${target}`);
  names = fs.readdirSync(resolved).filter((name) => name.toLowerCase().endsWith('.jsonl')).sort();
  if (!names.length) failUsage(`no .jsonl files under ${target}`);
  return names.map((name) => ({ name, text: fs.readFileSync(path.join(resolved, name), 'utf8') }));
}

if (opts.check) {
  runCheck();
  process.exit(0);
}

if (opts.emitSamples) {
  fs.mkdirSync(opts.emitSamples, { recursive: true });
  for (const [name, text] of serializeSampleFiles()) {
    fs.writeFileSync(path.join(opts.emitSamples, name), text);
    console.log(`wrote ${path.join(opts.emitSamples, name)}`);
  }
  process.exit(0);
}

if (!opts.jsonl) failUsage('--jsonl <path> is required (or use --check / --emit-samples / --help)');
const files = collectInputFiles(opts.jsonl);
const result = aggregate(files, opts.jsonl);
const report = opts.format === 'json' ? renderJson(result, opts.baseline) : renderMd(result, opts.baseline);
process.stdout.write(report);
if (opts.out) {
  fs.mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  fs.writeFileSync(opts.out, report);
  console.error(`summarize.mjs: report also written to ${opts.out}`);
}

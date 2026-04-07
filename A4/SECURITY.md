# Security Design — Multi-Source IDS

> CS8.403 · Lab Assignment 4 · IIIT Hyderabad

---

## 1. Core Security Requirement

> **A Critical alert is only raised when evidence from at least two independent sensors agrees within the sliding time window, OR when a deterministic multi-step attack pattern is detected.**

This requirement is enforced at **two independent layers**:

### Layer 1 — CorrelationEngine (`correlation_engine.py`)

Inside `_trigger_alert()`, before an alert is emitted:

```python
if len(sensors) == 1 and severity == 'Critical':
    severity = 'High'
    description = "[Downgraded: Single Sensor] " + description
```

In addition, the `_cross_source_seen` tracker upgrades an existing `High` alert to `Critical` the moment a *second independent sensor* produces corroborating evidence for the same `(rule, src_ip)` key within the window.

### Layer 2 — AlertManager (`alert_manager.py`)

Defence-in-depth check: any alert that arrives at the AlertManager with a single sensor and `Critical` severity is downgraded to `High` and the description is prefixed with `[Downgraded by AM: Single Sensor]`. This catches any future code path that bypasses Layer 1.

---

## 2. Threat Model

| Adversary capability          | System response |
|-------------------------------|-----------------|
| Brute-force authentication    | `BruteForce` rule (≥6 failures / 60 s, score ≥ 6.0) |
| Fast port scanning            | `FastPortScan` rule (>20 ports / <5 s) |
| Slow / evasive port scanning  | `SlowPortScan` rule (>20 ports / ≥5 s) with longer window |
| Replay / noise injection      | `ReplayAttack` rule (≥15 identical events / 10 s) |
| Sensor disabling              | Single-sensor alerts still fire at `High`; Critical requires 2 sensors |
| Multi-step compromise         | `MultiStepCompromise` rule correlates brute force → login → process chain |
| Statistical flooding          | z-score anomaly detector fires at z > 3.0 |

The adversary is assumed to have **limited capabilities**: they cannot compromise the IDS host itself, inject arbitrary code into the sensor processes, or spoof the inter-process queues.

---

## 3. Alert Deduplication & Cooldown

Duplicate alerts are suppressed using a per-signature cooldown:

```
signature = f"{rule_name}_{severity}_{src_ip}"
```

Including `src_ip` in the signature ensures that concurrent attacks from **different sources** are never collapsed. The default cooldown window is **10 seconds**.

---

## 4. Sliding Time Window

The CorrelationEngine maintains a sliding deque of `IDSEvent` objects pruned to a **60-second window**. Rules only consider evidence within this window, which:

- Prevents stale events from contributing to new alerts.
- Limits memory growth proportionally to event rate.
- Allows slow-scan detection without holding state indefinitely.

The IP-anomaly history uses a **5× wider window (300 s)** to maintain a stable baseline for z-score computation.

---

## 5. Severity Scoring

Severity levels and their operational meaning:

| Level    | Meaning |
|----------|---------|
| Info     | Informational; no action required |
| Low      | Suspicious but likely benign or evasive low-priority activity |
| Medium   | Moderate confidence attack; investigate |
| High     | Strong single-source evidence; prioritise response |
| Critical | Cross-source confirmed compromise; immediate action required |

---

## 6. False Positive Reduction

Three mechanisms limit false positives:

1. **Score thresholds** — raw event counts are weighted; a single noisy event cannot trigger a rule.
2. **Time-span checks** — port-scan rules require a minimum number of *distinct* ports; replays must occur within a tight 10-second burst window.
3. **Cooldown suppression** — repeated firing of the same rule for the same source is rate-limited to one alert per 10 seconds.

---

## 7. Design Decisions & Trade-offs

| Decision | Rationale |
|----------|-----------|
| Multiprocessing over threading | True parallelism; sensor faults are isolated from the correlation engine |
| JSON event schema | Human-readable, language-agnostic, easy to log and replay |
| Dedup keyed on `(rule, severity, src_ip)` | Prevents IP-A's attack from suppressing IP-B's independent attack |
| z-score anomaly flagged as `TrafficAnomaly` | Kept separate from deterministic rules so FP count is measured independently |
| Defence-in-depth severity enforcement | Prevents a future code change from accidentally issuing Critical on single-sensor evidence |
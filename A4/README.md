# Multi-Source Intrusion Detection System (IDS)


## Overview

A lightweight, modular IDS that correlates evidence from **network** and **host** sensors using rule-based and statistical detection. All components communicate through a unified JSON event schema and run as independent processes on a single machine.

---

## Architecture


| Component            | File                   | Role |
|----------------------|------------------------|------|
| NetworkSensor        | `network_sensor.py`    | Normalises raw network flows → IDSEvent |
| HostSensor           | `host_sensor.py`       | Normalises host logs → IDSEvent |
| CorrelationEngine    | `correlation_engine.py`| Sliding-window rules + z-score anomaly detection |
| AlertManager         | `alert_manager.py`     | Deduplication, cooldown, severity enforcement |
| Simulator            | `simulator.py`         | Generates benign & attack traffic |
| Schemas              | `schemas.py`           | Shared `IDSEvent` / `Alert` dataclasses |
| Entry point          | `main.py`              | Process orchestration + metrics report |

---

## Requirements

- Python 3.9+
- `psutil` (optional, for CPU/RAM metrics)

```bash
pip install psutil
```

---

## Running

```bash
# Run all scenarios (default)
python main.py

# Run a single scenario
python main.py --scenario brute_force
python main.py --scenario fast_port_scan
python main.py --scenario slow_port_scan
python main.py --scenario noise
python main.py --scenario sensor_fail
python main.py --scenario multi_step
```

Alerts are written to `alerts.log` (one JSON object per line) and a colour-coded summary is printed to the terminal at the end of the run.

---

## Detection Rules

| # | Rule Name           | Trigger condition                                            | Default Severity |
|---|---------------------|--------------------------------------------------------------|-----------------|
| 1 | `FastPortScan`      | >20 distinct ports from one IP within <5 s                  | Medium          |
| 2 | `SlowPortScan`      | >20 distinct ports from one IP over ≥5 s                    | Low             |
| 3 | `BruteForce`        | >5 failed logins from one IP within 60 s                    | High            |
| 4 | `SuspiciousProcess` | Known malicious process name executed (cmd.exe, nmap, …)    | Medium          |
| 5 | `ReplayAttack`      | ≥15 identical events from one IP within 10 s                | Low             |
| 6 | `MultiStepCompromise` | Brute force + successful login + suspicious process chain  | Critical        |
| 7 | `TrafficAnomaly`    | z-score > 3.0 on per-IP request rate (anomaly detector)     | Medium          |


### Anomaly detection (§7)

```
z_f = (f_t − μ_f) / (σ_f + ε)    [alert when z_f > 3.0]
```

---

## Metrics reported

- **Precision / Recall / F1**
- **False positive & false negative counts**
- **Alert latency** (first / average / last, measured from run start)
- **CPU & RAM** usage (sampled every 1 s via psutil)

---

## Output files

| File         | Description                       |
|--------------|-----------------------------------|
| `alerts.log` | JSONL alert log (one alert / line)|

---

## Notes

- All components share the same `IDSEvent` / `Alert` schema defined in `schemas.py`.
- Critical alerts require evidence from ≥2 independent sensors (enforced in both `CorrelationEngine` and `AlertManager`).
- Alert deduplication uses a 10-second cooldown keyed on `(rule, severity, src_ip)`.
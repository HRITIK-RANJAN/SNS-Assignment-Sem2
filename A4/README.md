# Multi-Source Intrusion Detection System (IDS)

A lightweight, modular Intrusion Detection System (IDS) designed to combine information from multiple independent sensors (Network and Host) to improve detection accuracy and rigorously reduce false positives.

## Key Features

- **Multi-sensor Correlation**: Seamlessly correlates network flows and host application logs within a sliding time window.
- **Rule-based & Statistical Anomaly Detection**: 
  - Supports 6 deterministic rules: Fast/Slow Port Scans, Brute-force Logins, Suspicious Process Execution, Replay Attacks, and Multi-step Compromise.
  - Includes a statistical Anomaly Detector utilizing Z-scores to identify abnormal request velocities.
- **Robust Alert Manager**: Enforces strict severity escalation constraints (e.g., `Critical` alerts strictly require cross-source affirmation), deduplicates occurrences, and throttles alert floods using cooldown logic.
- **Built-in Simulation Harness**: Includes a full attack suite to test all components natively without requiring external frameworks (like Snort or Suricata).

## System Architecture

The IDS is divided into discrete components running as independent processes, mimicking a distributed architecture:
1. **Network Sensor (`src/network_sensor.py`)**: Captures and parses network flow metadata.
2. **Host Sensor (`src/host_sensor.py`)**: Monitors simulated host-level logs (e.g., logins, process executions).
3. **Correlation Engine (`src/correlation_engine.py`)**: Ingests multi-sensor events, applies sliding-window logic, and generates raw alerts.
4. **Alert Manager (`src/alert_manager.py`)**: Deduplicates, scores, and manages finalized alerts.
5. **Simulator (`src/simulator.py`)**: Generates testing traffic (benign and malicious).
6. **Main Orchestrator (`src/main.py`)**: The single entry point that boots and coordinates all the above processes.

## Requirements
- Python 3.8+
- `psutil` (Optional, strictly used for CPU/Memory metric collection during evaluation)

---

## Installation & Setup

1. Check your Python environment and install the required metrics library:
   ```bash
   pip install psutil
   ```
2. Navigate to the project root directory.

---

## How to Run & Execution Sequence

You do **not** need to start the sensors, engines, or alert managers manually in sequence. The system is designed with a central orchestrator. 

**The only file you need to run is `src/main.py`.** 

When executed, `main.py` automatically initializes the `multiprocessing` queues and starts the sensors, correlation engine, and alert manager in the correct operational sequence before invoking the attack simulator.

### 1. Run the Full Test Suite
To run all attack scenarios sequentially (including benign baselines):
```bash
cd src
python3 main.py --scenario all
```
*(Note: Please allow approximately 45 seconds for all scenarios and metrics to gracefully evaluate and terminate).*

### 2. Target Specific Scenarios
If you wish to test or debug individual attacks, you can specify them via the `--scenario` flag:
```bash
cd src
python3 main.py --scenario brute_force
python3 main.py --scenario fast_port_scan
python3 main.py --scenario slow_port_scan
python3 main.py --scenario noise
python3 main.py --scenario sensor_fail
python3 main.py --scenario multi_step
```

### 3. Viewing the Results
Once the orchestrator completes the tests and shuts down the subsystems gracefully, it will output:
1. A summary of **Total Alerts Generated** categorized by Severity and Rule.
2. **Performance Metrics** including Precision, Recall, F1-Score, and False Positives.
3. Detailed event records will be appended to `src/alerts.log` in standard JSON format for your review.

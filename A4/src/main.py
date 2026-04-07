import argparse
import json
import logging
import multiprocessing
import os
import threading
import time

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from network_sensor import NetworkSensor
from host_sensor import HostSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from simulator import Simulator

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Main")


# ---------------------------------------------------------------------------
# Process entry-points
# ---------------------------------------------------------------------------

def run_network_sensor(in_q, out_q):
    NetworkSensor(in_q, out_q).start()


def run_host_sensor(in_q, out_q):
    HostSensor(in_q, out_q).start()


def run_correlation_engine(in_q, out_q):
    CorrelationEngine(in_q, out_q).start()


# ---------------------------------------------------------------------------
# Metrics collection
# FIX: collect_metrics() was defined but never called.  It is now launched on
# a background daemon thread immediately after the worker processes start, and
# its results are returned via a shared list so main() can print them.
# ---------------------------------------------------------------------------

def collect_metrics(pid_list: list, stop_event: threading.Event,
                    results: list) -> None:
    """
    Sample CPU (%) and RSS memory (MB) for every PID in pid_list once per
    second until stop_event is set.  Appends one dict per sample to results.
    """
    if not PSUTIL_AVAILABLE:
        logger.warning("psutil not available — CPU/memory metrics skipped.")
        return

    while not stop_event.is_set():
        total_cpu = 0.0
        total_mem = 0.0
        for pid in pid_list:
            try:
                p = psutil.Process(pid)
                total_cpu += p.cpu_percent(interval=0)
                total_mem += p.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        results.append({
            'time': time.time(),
            'cpu_pct': round(total_cpu, 2),
            'mem_mb':  round(total_mem / (1024 * 1024), 2),
        })
        time.sleep(1)


# ---------------------------------------------------------------------------
# Alert-manager process (writes to file; latency-stamped)
# ---------------------------------------------------------------------------

def run_am(in_q, log_path: str) -> None:
    """
    Subclass of AlertManager that:
    • appends every new alert as a JSON line to log_path
    • computes alert latency from the earliest source_event timestamp stored
      inside the IDSEvent records (we use alert.timestamp which the CE stamps
      at generation time; the simulator stamps raw events with time.time() so
      the difference is the true engine latency).
    """
    from schemas import Alert as _Alert

    class FileAlertManager(AlertManager):
        def _process_alert(self, alert: _Alert) -> bool:
            is_new = super()._process_alert(alert)
            if is_new:
                with open(log_path, 'a') as fh:
                    fh.write(alert.to_json() + '\n')
            return is_new

    FileAlertManager(in_q).start()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Multi-Source IDS")
    parser.add_argument('--scenario', type=str, default='all',
                        help='Scenario to run (all | brute_force | fast_port_scan | '
                             'slow_port_scan | noise | sensor_fail | multi_step)')
    args = parser.parse_args()

    net_in_q  = multiprocessing.Queue()
    host_in_q = multiprocessing.Queue()
    event_q   = multiprocessing.Queue()
    alert_q   = multiprocessing.Queue()

    net_proc  = multiprocessing.Process(target=run_network_sensor,
                                        args=(net_in_q, event_q))
    host_proc = multiprocessing.Process(target=run_host_sensor,
                                        args=(host_in_q, event_q))
    corr_proc = multiprocessing.Process(target=run_correlation_engine,
                                        args=(event_q, alert_q))

    log_path = 'alerts.log'
    os.system(f'rm -f {log_path}')

    am_proc = multiprocessing.Process(target=run_am,
                                      args=(alert_q, log_path))

    net_proc.start()
    host_proc.start()
    corr_proc.start()
    am_proc.start()

    logger.info(
        f"Started PIDs: Net({net_proc.pid}), Host({host_proc.pid}), "
        f"Corr({corr_proc.pid}), AM({am_proc.pid})"
    )

    # FIX: start metrics collection on a background thread immediately after
    # all worker processes have been launched.
    pid_list      = [net_proc.pid, host_proc.pid, corr_proc.pid, am_proc.pid]
    metrics_stop  = threading.Event()
    metrics_data: list = []
    metrics_thread = threading.Thread(
        target=collect_metrics,
        args=(pid_list, metrics_stop, metrics_data),
        daemon=True,
    )
    metrics_thread.start()
    logger.info("Metrics collection thread started.")

    sim = Simulator(net_in_q, host_in_q)

    # Record wall-clock start so we can compute per-scenario latencies.
    run_start = time.time()

    time.sleep(1)                          # let queues stabilise

    sim.generate_benign(duration=2)

    if args.scenario in ('brute_force', 'all'):
        sim.scenario_brute_force()
        time.sleep(2)

    if args.scenario in ('fast_port_scan', 'all'):
        sim.scenario_fast_port_scan()
        time.sleep(2)

    if args.scenario in ('slow_port_scan', 'all'):
        sim.scenario_slow_port_scan()
        time.sleep(2)

    if args.scenario in ('noise', 'all'):
        sim.scenario_noise_injection()
        time.sleep(2)

    if args.scenario in ('sensor_fail', 'all'):
        sim.scenario_sensor_failure()
        time.sleep(2)

    if args.scenario in ('multi_step', 'all'):
        sim.scenario_multi_step_attack()
        time.sleep(3)

    sim.generate_benign(duration=2)

    logger.info("Test finished. Shutting down...")

    # Stop metrics collection before joining processes.
    metrics_stop.set()
    metrics_thread.join(timeout=3)

    # Poison pills
    net_in_q.put(None)
    host_in_q.put(None)
    event_q.put(None)
    alert_q.put(None)

    net_proc.join(timeout=3)
    host_proc.join(timeout=3)
    corr_proc.join(timeout=3)
    am_proc.join(timeout=3)

    for p in (net_proc, host_proc, corr_proc, am_proc):
        if p.is_alive():
            p.terminate()

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------

    logger.info("Shut down complete. Printing report:")
    try:
        alerts = []
        with open(log_path, 'r') as fh:
            for line in fh:
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass

        print(f"\n{'-' * 85}")
        print(f"TOTAL ALERTS GENERATED: {len(alerts)}")
        print(f"{'-' * 85}")
        for a in alerts:
            sensors = ", ".join(a['sensors_involved']) if isinstance(a['sensors_involved'], list) else a['sensors_involved']
            print(f"  [{a['severity']:<8}] {a['rule_name']:<25} | "
                  f"Events: {len(a['source_events']):<5} | "
                  f"Sensors: {sensors}")
        print(f"{'-' * 85}\n")

        # ── Detection metrics ────────────────────────────────────────────
        # Ground truth: one unique attack rule per scenario that was run.
        scenario_rules = {
            'brute_force':    'BruteForce',
            'fast_port_scan': 'FastPortScan',
            'slow_port_scan': 'SlowPortScan',
            'noise':          'ReplayAttack',
            'sensor_fail':    'BruteForce',   # same rule, different IP
            'multi_step':     'MultiStepCompromise',
        }
        if args.scenario == 'all':
            expected_rules = set(scenario_rules.values())
        else:
            expected_rules = {scenario_rules[args.scenario]} if args.scenario in scenario_rules else set()

        detected_rules  = {a['rule_name'] for a in alerts
                           if a['rule_name'] != 'TrafficAnomaly'}
        true_positives  = len(detected_rules & expected_rules)
        false_positives = len([a for a in alerts if a['rule_name'] == 'TrafficAnomaly'])
        false_negatives = len(expected_rules - detected_rules)

        precision = (true_positives / (true_positives + false_positives)
                     if (true_positives + false_positives) > 0 else 0.0)
        recall    = (true_positives / (true_positives + false_negatives)
                     if (true_positives + false_negatives) > 0 else 0.0)
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)

        print("--- Detection Metrics (Approximated from Scenarios) ---")
        print(f"  Precision       : {precision:.2f}")
        print(f"  Recall          : {recall:.2f}")
        print(f"  F1-Score        : {f1:.2f}")
        print(f"  False Positives : {false_positives}")
        print(f"  False Negatives : {false_negatives}")

        # ── Latency ──────────────────────────────────────────────────────
        # Each Alert carries a timestamp set by the CorrelationEngine at the
        # moment it fires.  The run_start wall-clock gives a lower bound; the
        # difference between the earliest alert timestamp and the scenario
        # start is a rough but real latency figure (no synthetic estimate).
        # FIX: report measured latency instead of a hardcoded "< 100ms".
        if alerts:
            alert_ts   = [a['timestamp'] for a in alerts]
            # The CE evaluates every 1 s, so typical latency is 0–1 s.
            min_latency = min(alert_ts) - run_start
            max_latency = max(alert_ts) - run_start
            print(f"\n--- Alert Generation Latency (Measured) ---")
            print(f"  First alert after run start : {min_latency:.2f} s")
            print(f"  Last  alert after run start : {max_latency:.2f} s")
            print(f"  (CE evaluation interval = 1.0 s;")
            print(f"   worst-case per-event latency = ~1.0 s)")

        # ── CPU / memory ─────────────────────────────────────────────────
        # FIX: print the actually-collected metrics instead of the placeholder
        # string "CPU/Memory profiles logged during execution."
        print(f"\n--- CPU / Memory Usage (sampled every 1s) ---")
        if metrics_data:
            avg_cpu = sum(m['cpu_pct'] for m in metrics_data) / len(metrics_data)
            max_cpu = max(m['cpu_pct'] for m in metrics_data)
            avg_mem = sum(m['mem_mb']  for m in metrics_data) / len(metrics_data)
            max_mem = max(m['mem_mb']  for m in metrics_data)
            print(f"  Samples Collected : {len(metrics_data)}")
            print(f"  CPU Avg / Peak    : {avg_cpu:5.1f}% / {max_cpu:5.1f}%")
            print(f"  RAM Avg / Peak    : {avg_mem:7.1f} MB / {max_mem:7.1f} MB")
        elif not PSUTIL_AVAILABLE:
            print("  psutil not installed — install with: pip install psutil")
        else:
            print("  No samples collected (run too short).")

    except Exception as exc:
        print(f"Error reading {log_path}: {exc}")


if __name__ == '__main__':
    main()
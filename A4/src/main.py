import argparse
import json
import logging
import multiprocessing
import os
import re
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Main")

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _extract_ip(description: str) -> str:
    match = _IP_RE.search(description or '')
    return match.group(1) if match else ''


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
# ---------------------------------------------------------------------------

def collect_metrics(pid_list: list, stop_event: threading.Event, results: list) -> None:
    """
    Sample CPU (%) and RSS memory (MB) for every PID in pid_list once per
    second until stop_event is set. Appends one dict per sample to results.
    """
    if not PSUTIL_AVAILABLE:
        logger.warning("psutil not available - CPU/memory metrics skipped.")
        return

    processes = {}
    for pid in pid_list:
        try:
            proc = psutil.Process(pid)
            # Prime the moving counter; following reads become meaningful.
            proc.cpu_percent(interval=None)
            processes[pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    while not stop_event.is_set():
        total_cpu = 0.0
        total_mem = 0.0
        for pid, proc in list(processes.items()):
            try:
                total_cpu += proc.cpu_percent(interval=None)
                total_mem += proc.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                del processes[pid]

        results.append({
            'time': time.time(),
            'cpu_pct': round(total_cpu, 2),
            'mem_mb': round(total_mem / (1024 * 1024), 2),
        })
        time.sleep(1)


# ---------------------------------------------------------------------------
# Alert-manager process (writes to file)
# ---------------------------------------------------------------------------

def run_am(in_q, log_path: str) -> None:
    """
    Subclass of AlertManager that appends each accepted alert to log_path.
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
    parser.add_argument(
        '--scenario',
        type=str,
        default='all',
        help=('Scenario to run (all | brute_force | fast_port_scan | '
              'slow_port_scan | noise | sensor_fail | multi_step)')
    )
    args = parser.parse_args()

    net_in_q = multiprocessing.Queue()
    host_in_q = multiprocessing.Queue()
    event_q = multiprocessing.Queue()
    alert_q = multiprocessing.Queue()

    net_proc = multiprocessing.Process(target=run_network_sensor, args=(net_in_q, event_q))
    host_proc = multiprocessing.Process(target=run_host_sensor, args=(host_in_q, event_q))
    corr_proc = multiprocessing.Process(target=run_correlation_engine, args=(event_q, alert_q))

    log_path = 'alerts.log'
    os.system(f'rm -f {log_path}')

    am_proc = multiprocessing.Process(target=run_am, args=(alert_q, log_path))

    net_proc.start()
    host_proc.start()
    corr_proc.start()
    am_proc.start()

    logger.info(
        f"Started PIDs: Net({net_proc.pid}), Host({host_proc.pid}), "
        f"Corr({corr_proc.pid}), AM({am_proc.pid})"
    )

    pid_list = [net_proc.pid, host_proc.pid, corr_proc.pid, am_proc.pid]
    metrics_stop = threading.Event()
    metrics_data: list = []
    metrics_thread = threading.Thread(
        target=collect_metrics,
        args=(pid_list, metrics_stop, metrics_data),
        daemon=True,
    )
    metrics_thread.start()
    logger.info("Metrics collection thread started.")

    sim = Simulator(net_in_q, host_in_q)
    run_start = time.time()

    time.sleep(1)
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

    metrics_stop.set()
    metrics_thread.join(timeout=3)

    net_in_q.put(None)
    host_in_q.put(None)
    event_q.put(None)
    alert_q.put(None)

    net_proc.join(timeout=3)
    host_proc.join(timeout=3)
    corr_proc.join(timeout=3)
    am_proc.join(timeout=3)

    for proc in (net_proc, host_proc, corr_proc, am_proc):
        if proc.is_alive():
            proc.terminate()

    logger.info("Shut down complete. Printing report:")
    try:
        alerts = []
        with open(log_path, 'r') as fh:
            for line in fh:
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

        print(f"\n{'-' * 85}")
        print(f"TOTAL ALERTS GENERATED: {len(alerts)}")
        print(f"{'-' * 85}")
        for alert in alerts:
            sensors = ", ".join(alert['sensors_involved']) if isinstance(alert['sensors_involved'], list) else alert['sensors_involved']
            print(
                f"  [{alert['severity']:<8}] {alert['rule_name']:<25} | "
                f"Events: {len(alert['source_events']):<5} | "
                f"Sensors: {sensors} | "
                f"SrcIP: {alert.get('src_ip') or _extract_ip(alert.get('description', '')) or '-'}"
            )
        print(f"{'-' * 85}\n")

        # Incident-level ground truth uses (rule_name, src_ip).
        scenario_truth = {
            'brute_force': [
                ('BruteForce', '192.168.1.100'),
                ('CrossSourceBruteForce', '192.168.1.100'),
            ],
            'fast_port_scan': [('FastPortScan', '192.168.1.101')],
            'slow_port_scan': [('SlowPortScan', '192.168.1.102')],
            'noise': [('ReplayAttack', '192.168.1.103')],
            'sensor_fail': [('BruteForce', '192.168.1.104')],
            'multi_step': [('MultiStepCompromise', '192.168.1.105')],
        }

        if args.scenario == 'all':
            expected_incidents = {
                incident
                for incidents in scenario_truth.values()
                for incident in incidents
            }
        else:
            expected_incidents = set(scenario_truth.get(args.scenario, []))

        detected_incidents = set()
        for alert in alerts:
            ip = alert.get('src_ip') or _extract_ip(alert.get('description', ''))
            rule = alert.get('rule_name', '')
            if rule and ip:
                detected_incidents.add((rule, ip))

        true_positives = len(detected_incidents & expected_incidents)
        false_positives = len(detected_incidents - expected_incidents)
        false_negatives = len(expected_incidents - detected_incidents)

        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0 else 0.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0 else 0.0
        )
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0 else 0.0
        )

        print("--- Detection Metrics (Incident-Level) ---")
        print(f"  Precision       : {precision:.2f}")
        print(f"  Recall          : {recall:.2f}")
        print(f"  F1-Score        : {f1:.2f}")
        print(f"  True Positives  : {true_positives}")
        print(f"  False Positives : {false_positives}")
        print(f"  False Negatives : {false_negatives}")

        if alerts:
            alert_ts = [a['timestamp'] for a in alerts]
            min_latency = min(alert_ts) - run_start
            max_latency = max(alert_ts) - run_start
            print("\n--- Alert Generation Latency (Measured) ---")
            print(f"  First alert after run start : {min_latency:.2f} s")
            print(f"  Last  alert after run start : {max_latency:.2f} s")
            print("  (CE evaluation interval = 1.0 s;")
            print("   worst-case per-event latency = ~1.0 s)")

        print("\n--- CPU / Memory Usage (sampled every 1s) ---")
        if metrics_data:
            avg_cpu = sum(m['cpu_pct'] for m in metrics_data) / len(metrics_data)
            max_cpu = max(m['cpu_pct'] for m in metrics_data)
            avg_mem = sum(m['mem_mb'] for m in metrics_data) / len(metrics_data)
            max_mem = max(m['mem_mb'] for m in metrics_data)
            print(f"  Samples Collected : {len(metrics_data)}")
            print(f"  CPU Avg / Peak    : {avg_cpu:5.1f}% / {max_cpu:5.1f}%")
            print(f"  RAM Avg / Peak    : {avg_mem:7.1f} MB / {max_mem:7.1f} MB")
        elif not PSUTIL_AVAILABLE:
            print("  psutil not installed - install with: pip install psutil")
        else:
            print("  No samples collected (run too short).")

    except Exception as exc:
        print(f"Error reading {log_path}: {exc}")


if __name__ == '__main__':
    main()

import json
import logging
import multiprocessing
import time
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional, Tuple
from schemas import IDSEvent, Alert
import uuid

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CorrelationEngine")

# ---------------------------------------------------------------------------
# Per-rule evidence weights used to implement score(u,t) = Σ w(e) from §7.
# Each weight reflects how strongly that evidence type implicates an attack.
# ---------------------------------------------------------------------------
EVENT_WEIGHTS: Dict[str, float] = {
    'network_port_probe':    0.5,   # a single port connection attempt
    'host_login_failure':    1.0,   # failed authentication
    'host_login_success':    1.5,   # successful auth (after failures = suspicious)
    'host_suspicious_proc':  2.0,   # known malicious process name
    'network_replay':        0.3,   # one duplicate packet
    'default':               0.5,
}

# Minimum aggregate weight required to trigger each rule.
SCORE_THRESHOLDS: Dict[str, float] = {
    'BruteForce':         6.0,   # ≥6 failed logins × 1.0
    'CrossSourceBruteForce': 9.0,  # combined host+network evidence
    'FastPortScan':       8.0,   # ≥16 port probes × 0.5 (>20 ports)
    'SlowPortScan':       8.0,
    'ReplayAttack':       4.5,   # ≥15 duplicates × 0.3
    'MultiStepCompromise': 5.0,  # sum of cross-sensor combined evidence
}

# Keep this list intentionally tight to avoid broad false positives.
SUSPICIOUS_PROCESS_NAMES = {
    'nc', 'netcat', 'nmap', 'mimikatz', 'psexec',
    'powershell.exe', 'cmd.exe'
}


def _weight(event: IDSEvent) -> float:
    """Return the per-event contribution to the evidence score."""
    if event.sensor == 'network' and event.event_type == 'connection':
        return EVENT_WEIGHTS['network_port_probe']
    if event.sensor == 'host' and event.event_type == 'login':
        if event.action == 'failed':
            return EVENT_WEIGHTS['host_login_failure']
        if event.action == 'success':
            return EVENT_WEIGHTS['host_login_success']
    if event.sensor == 'host' and event.event_type == 'process':
        return EVENT_WEIGHTS['host_suspicious_proc']
    return EVENT_WEIGHTS['default']


def _score(events: List[IDSEvent]) -> float:
    """Aggregate evidence score: score(u,t) = Σ w(e)."""
    return sum(_weight(e) for e in events)


def _event_signature(event: IDSEvent) -> str:
    """Stable event signature used for replay/noise detection."""
    details = json.dumps(event.details or {}, sort_keys=True)
    return (
        f"{event.sensor}:{event.event_type}:{event.src_ip}:{event.dst_ip}:"
        f"{event.src_port}:{event.dst_port}:{event.protocol}:{event.user}:"
        f"{event.action}:{event.process_name}:{event.packet_count}:{event.byte_count}:{details}"
    )


class CorrelationEngine:
    def __init__(self, event_queue: multiprocessing.Queue,
                 alert_queue: multiprocessing.Queue,
                 window_size: float = 60.0):
        self.event_queue = event_queue
        self.alert_queue = alert_queue
        self.window_size = window_size
        self.running = False

        # Sliding window of events kept in chronological order.
        self.events_window: deque = deque()

        # Per-IP request timestamps for z-score anomaly detection.
        self.ip_request_history: Dict[str, List[float]] = defaultdict(list)

        # FIX (cross-source elevation): track the highest severity that has
        # been seen for each (rule, src_ip) pair within the current window.
        # When two independent sensors both report the same threat for the same
        # source, their combined evidence is eligible for Critical.
        self._cross_source_seen: Dict[Tuple[str, str], Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self.running = True
        logger.info("CorrelationEngine started.")
        last_eval_time = 0.0
        while self.running:
            try:
                msg = self.event_queue.get(timeout=0.5)
                if msg is None:  # poison pill
                    break
                event = IDSEvent.from_json(msg)
                self._add_event(event)

                now = time.time()
                if now - last_eval_time > 1.0:
                    self._evaluate_rules()
                    self._evaluate_anomalies()
                    last_eval_time = now

            except multiprocessing.queues.Empty:
                now = time.time()
                if now - last_eval_time > 1.0:
                    self._evaluate_rules()
                    self._evaluate_anomalies()
                    last_eval_time = now
            except Exception as e:
                import traceback
                logger.error(f"Error in CorrelationEngine: {e}")
                traceback.print_exc()

        logger.info("CorrelationEngine stopped.")

    def stop(self):
        self.running = False

    # ------------------------------------------------------------------
    # Event ingestion and window maintenance
    # ------------------------------------------------------------------

    def _add_event(self, event: IDSEvent):
        now = time.time()
        self.events_window.append(event)

        if event.src_ip:
            self.ip_request_history[event.src_ip].append(now)

        # Prune the sliding window.
        while self.events_window and (now - self.events_window[0].timestamp > self.window_size):
            self.events_window.popleft()

        # Prune IP anomaly history (keep a wider 5× window for stable baselines).
        for ip, times in list(self.ip_request_history.items()):
            while times and (now - times[0] > self.window_size * 5):
                times.pop(0)
            if not times:
                del self.ip_request_history[ip]

        # Prune stale cross-source tracking entries.
        stale = [k for k, v in self._cross_source_seen.items()
                 if now - v['first_seen'] > self.window_size]
        for k in stale:
            del self._cross_source_seen[k]

    # ------------------------------------------------------------------
    # Alert emission
    # ------------------------------------------------------------------

    def _trigger_alert(self, rule_name: str, description: str,
                       severity: str, events: List[IDSEvent],
                       src_ip: str = '') -> None:
        sensors = list(set(e.sensor for e in events))

        # Core Security Requirement: single-sensor evidence cannot exceed High.
        if len(sensors) == 1 and severity == 'Critical':
            severity = 'High'
            description = f"[Downgraded: Single Sensor] {description}"

        # FIX (cross-source elevation): record this alert in the cross-source
        # tracker keyed on (rule_name, src_ip).  If we later receive evidence
        # for the SAME rule from a DIFFERENT sensor within the window, elevate
        # to Critical because two independent channels now agree.
        key = (rule_name, src_ip or '')
        if key in self._cross_source_seen:
            prior = self._cross_source_seen[key]
            combined_sensors = set(prior['sensors']) | set(sensors)
            if len(combined_sensors) >= 2 and severity != 'Critical':
                severity = 'Critical'
                description = (
                    f"[Elevated: Cross-Source Confirmation — "
                    f"{', '.join(sorted(combined_sensors))}] {description}"
                )
                # Merge evidence from both detections.
                events = list({e.event_id: e
                               for e in (prior['events'] + events)}.values())
                sensors = list(combined_sensors)
        # Upsert the tracker with the latest sensor/events for this key.
        self._cross_source_seen[key] = {
            'sensors': sensors,
            'events': events,
            'first_seen': self._cross_source_seen.get(key, {}).get(
                'first_seen', time.time()),
        }

        # FIX (latency): stamp when the alert is actually generated so that
        # main.py can compute true event-to-alert latency if needed.
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=time.time(),
            severity=severity,
            description=description,
            source_events=[e.event_id for e in events],
            rule_name=rule_name,
            sensors_involved=sensors,
            src_ip=src_ip or None,
        )
        self.alert_queue.put(alert.to_json())

    # ------------------------------------------------------------------
    # Rule evaluation  (4: ≥6 non-trivial deterministic rules)
    # ------------------------------------------------------------------

    def _evaluate_rules(self):
        ip_ports:           Dict[str, set]         = defaultdict(set)
        ip_network_events:  Dict[str, List]        = defaultdict(list)
        ip_failed_logins:   Dict[str, List]        = defaultdict(list)
        ip_success_logins:  Dict[str, List]        = defaultdict(list)
        suspicious_procs:   List[IDSEvent]         = []
        event_hashes:       Dict[str, List]        = defaultdict(list)

        for e in self.events_window:
            if e.sensor == 'network' and e.src_ip:
                if e.dst_port:
                    ip_ports[e.src_ip].add(e.dst_port)
                ip_network_events[e.src_ip].append(e)

            if e.sensor == 'host':
                if e.event_type == 'login' and e.action == 'failed' and e.src_ip:
                    ip_failed_logins[e.src_ip].append(e)
                elif e.event_type == 'login' and e.action == 'success' and e.src_ip:
                    ip_success_logins[e.src_ip].append(e)
                elif e.event_type == 'process':
                    if e.process_name in SUSPICIOUS_PROCESS_NAMES:
                        suspicious_procs.append(e)

            # Hash for replay detection (excludes volatile fields).
            ehash = _event_signature(e)
            event_hashes[ehash].append(e)

        # ── Rules 1 & 2: Port scans ──────────────────────────────────────
        for ip, ports in ip_ports.items():
            events = ip_network_events[ip]
            if not events or len(ports) <= 20:
                continue
            score = _score(events)
            time_span = events[-1].timestamp - events[0].timestamp
            if time_span < 5.0:
                if score >= SCORE_THRESHOLDS['FastPortScan']:
                    self._trigger_alert(
                        "FastPortScan",
                        f"Fast port scan from {ip} targeting {len(ports)} ports "
                        f"(score={score:.1f})",
                        "Medium", events, src_ip=ip
                    )
            else:
                if score >= SCORE_THRESHOLDS['SlowPortScan']:
                    self._trigger_alert(
                        "SlowPortScan",
                        f"Slow port scan from {ip} targeting {len(ports)} ports "
                        f"(score={score:.1f})",
                        "Low", events, src_ip=ip
                    )

        # ── Rule 3: Cross-source brute-force confirmation ────────────────
        # Assignment clause: Critical when at least two independent sources
        # agree within the correlation window.
        for ip, failures in ip_failed_logins.items():
            if len(failures) <= 5:
                continue
            ssh_attempts = [e for e in ip_network_events.get(ip, []) if e.dst_port == 22]
            if len(ssh_attempts) <= 5:
                continue

            combined = failures + ssh_attempts
            first_ts = min(e.timestamp for e in combined)
            last_ts = max(e.timestamp for e in combined)
            if (last_ts - first_ts) >= self.window_size:
                continue

            score = _score(combined)
            if score >= SCORE_THRESHOLDS['CrossSourceBruteForce']:
                self._trigger_alert(
                    "CrossSourceBruteForce",
                    f"Cross-source agreement for brute force from {ip}: "
                    f"{len(failures)} failed logins + {len(ssh_attempts)} "
                    f"SSH attempts within window (score={score:.1f})",
                    "Critical", combined, src_ip=ip
                )

        # ── Rule 4: Brute-force login ────────────────────────────────────
        for ip, failures in ip_failed_logins.items():
            if len(failures) <= 5:
                continue
            time_span = failures[-1].timestamp - failures[0].timestamp
            if time_span >= 60.0:
                continue
            score = _score(failures)
            if score >= SCORE_THRESHOLDS['BruteForce']:
                self._trigger_alert(
                    "BruteForce",
                    f"Brute force login attempts from {ip} "
                    f"({len(failures)} failures, score={score:.1f})",
                    "High", failures, src_ip=ip
                )

        # ── Rule 5: Suspicious process ───────────────────────────────────
        for proc in suspicious_procs:
            self._trigger_alert(
                "SuspiciousProcess",
                f"Suspicious process execution: {proc.process_name}",
                "Medium", [proc],
                src_ip=proc.src_ip or ''
            )

        # ── Rule 6: Replay / noise injection ────────────────────────────
        for h, evts in event_hashes.items():
            if len(evts) <= 15:
                continue
            time_diff = evts[-1].timestamp - evts[0].timestamp
            if time_diff >= 10.0:
                continue
            # Replay/noise evidence uses dedicated replay weight.
            score = len(evts) * EVENT_WEIGHTS['network_replay']
            if score >= SCORE_THRESHOLDS['ReplayAttack']:
                src_ip = evts[0].src_ip or ''
                self._trigger_alert(
                    "ReplayAttack",
                    f"Replay or noise injection detected from {src_ip}. "
                    f"High volume of identical duplicate events "
                    f"(score={score:.1f})",
                    "Low", evts, src_ip=src_ip
                )

        # ── Rule 7: Multi-step compromise ────────────────────────────────
        for ip, failures in ip_failed_logins.items():
            if len(failures) <= 3:
                continue
            successes = ip_success_logins.get(ip, [])
            if not successes:
                continue
            for succ in successes:
                # Enforce sequence: login success must follow the failure burst.
                if succ.timestamp <= failures[-1].timestamp:
                    continue
                for sp in suspicious_procs:
                    if sp.timestamp <= succ.timestamp:
                        continue
                    if sp.user != succ.user:
                        continue
                    # Ensure the suspicious process belongs to the same source.
                    if sp.src_ip and sp.src_ip != ip:
                        continue
                    net_evts = ip_network_events.get(ip, [])
                    net_context = [n for n in net_evts if n.timestamp <= succ.timestamp]
                    combined = failures + [succ, sp] + net_context[:3]
                    score = _score(combined)
                    if score >= SCORE_THRESHOLDS['MultiStepCompromise']:
                        self._trigger_alert(
                            "MultiStepCompromise",
                            f"Multi-step compromise: Brute force followed by "
                            f"successful login and suspicious process from {ip} "
                            f"by user {succ.user} (score={score:.1f})",
                            "Critical", combined, src_ip=ip
                        )

    # ------------------------------------------------------------------
    # Anomaly detection  (§7: zf = (ft − μ) / (σ + ε))
    # ------------------------------------------------------------------

    def _evaluate_anomalies(self):
        now = time.time()

        for ip, times in self.ip_request_history.items():
            bins: Dict[int, int] = defaultdict(int)
            for t in times:
                bin_idx = int((now - t) / 5.0)
                bins[bin_idx] += 1

            # Build a deterministic baseline from fixed 5-second bins.
            max_bin = int(self.window_size)
            rates = [bins.get(i, 0) for i in range(max_bin + 1)]
            if len(rates) < 4:
                continue

            current_rate  = rates[0]
            history_rates = rates[1:]
            if sum(history_rates) < 10:
                # Not enough historical volume for a stable baseline.
                continue

            mu       = sum(history_rates) / len(history_rates)
            variance = sum((x - mu) ** 2 for x in history_rates) / len(history_rates)
            sigma    = variance ** 0.5
            epsilon  = 1e-5
            zf       = (current_rate - mu) / (sigma + epsilon)

            if zf > 3.0:
                recent_events = [
                    e for e in self.events_window
                    if e.src_ip == ip and (now - e.timestamp) < 5.0
                ]
                self._trigger_alert(
                    "TrafficAnomaly",
                    f"Statistical traffic anomaly for IP {ip} (z-score={zf:.2f}, "
                    f"rate={current_rate}, μ={mu:.1f}, σ={sigma:.1f})",
                    "Medium", recent_events, src_ip=ip
                )
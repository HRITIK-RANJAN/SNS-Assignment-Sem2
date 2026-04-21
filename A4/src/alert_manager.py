import json
import logging
import multiprocessing
import re
import time
from collections import defaultdict
from typing import Dict, Any, List, Optional
from schemas import Alert

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AlertManager")

# Regex used to extract the first IPv4 address from an alert description so
# that deduplication is keyed on (rule, severity, src_ip) rather than just
# (rule, severity).  This prevents a BruteForce from 192.168.1.100 from
# suppressing an independent BruteForce from 192.168.1.200.
_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _extract_ip(description: str) -> str:
    """Return the first IPv4 address found in description, or '' if none."""
    m = _IP_RE.search(description)
    return m.group(1) if m else ''


class AlertManager:
    def __init__(self, alert_queue: multiprocessing.Queue,
                 cooldown_seconds: float = 10.0,
                 max_alert_history: int = 5000):
        self.alert_queue = alert_queue
        self.cooldown_seconds = cooldown_seconds
        self.max_alert_history = max_alert_history
        self.running = False

        # FIX: key is now (rule_name, severity, src_ip) so that alerts for
        # different source IPs are never collapsed together.
        self.last_alerts: Dict[str, float] = {}
        self.generated_alerts: List[Alert] = []

    def start(self):
        self.running = True
        logger.info("AlertManager started.")
        while self.running:
            try:
                msg = self.alert_queue.get(timeout=1.0)
                if msg is None:  # poison pill
                    break

                # FIX: use Alert.from_json() directly — no more hasattr guard
                # or bare Alert(**dict) fallback.
                alert = Alert.from_json(msg)
                self._process_alert(alert)

            except multiprocessing.queues.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
        logger.info("AlertManager stopped.")

    def stop(self):
        self.running = False

    def get_generated_alerts(self) -> List[Alert]:
        return self.generated_alerts

    def _process_alert(self, alert: Alert) -> bool:
        # Prefer structured src_ip from alert payload; fall back to description
        # parsing only for backward compatibility with old alert formats.
        src_ip = alert.src_ip or _extract_ip(alert.description)
        signature = f"{alert.rule_name}_{alert.severity}_{src_ip}"

        now = time.time()

        # Prune stale dedup keys to avoid unbounded memory growth.
        dedup_ttl = self.cooldown_seconds * 6
        stale_keys = [k for k, ts in self.last_alerts.items() if now - ts > dedup_ttl]
        for k in stale_keys:
            del self.last_alerts[k]

        if signature in self.last_alerts:
            elapsed = now - self.last_alerts[signature]
            if elapsed < self.cooldown_seconds:
                # FIX: log the suppression instead of silently dropping it,
                # so operators can see cooldown activity in the logs.
                logger.debug(
                    f"COOLDOWN suppressed [{alert.severity}] {alert.rule_name} "
                    f"for {src_ip or 'unknown'} "
                    f"({self.cooldown_seconds - elapsed:.1f}s remaining)"
                )
                return False

        self.last_alerts[signature] = now

        # Secondary enforcement of the core security requirement.
        # The Correlation Engine already enforces this, but a defence-in-depth
        # check here catches any alert that bypasses the engine.
        if len(alert.sensors_involved) == 1 and alert.severity == 'Critical':
            alert.severity = 'High'
            alert.description = (
                f"[Downgraded by AM: Single Sensor] {alert.description}"
            )

        self.generated_alerts.append(alert)
        if len(self.generated_alerts) > self.max_alert_history:
            self.generated_alerts = self.generated_alerts[-self.max_alert_history:]
        logger.warning(
            f"ALERT [{alert.severity}] Rule:{alert.rule_name} | "
            f"Events:{len(alert.source_events)} | "
            f"Sensors:{alert.sensors_involved} | "
            f"DESC: {alert.description}"
        )
        return True
import logging
import multiprocessing
from typing import Dict, Any, Optional
from schemas import IDSEvent

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HostSensor")

class HostSensor:
    def __init__(self, input_queue: multiprocessing.Queue, output_queue: multiprocessing.Queue):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.running = False

    def start(self):
        self.running = True
        logger.info("HostSensor started.")
        while self.running:
            try:
                # input_queue contains raw log dictionaries
                raw_log: Dict[str, Any] = self.input_queue.get(timeout=1.0)
                if raw_log is None: # poison pill to stop
                    break
                event = self._process_log(raw_log)
                if event is not None:
                    self.output_queue.put(event.to_json())
            except multiprocessing.queues.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing host log: {e}")
        logger.info("HostSensor stopped.")

    def stop(self):
        self.running = False

    def _process_log(self, raw_log: Dict[str, Any]) -> Optional[IDSEvent]:
        # Expected keys: 'event_type', 'user', 'action', 'process_name', 'src_ip', 'details'
        required = ('event_type', 'user', 'action')
        missing = [k for k in required if k not in raw_log]
        if missing:
            logger.warning(f"Dropping malformed host log. Missing keys: {missing}")
            return None

        event_type = raw_log.get('event_type')
        user = raw_log.get('user')
        action = raw_log.get('action')
        process_name = raw_log.get('process_name')
        src_ip = raw_log.get('src_ip')
        details = raw_log.get('details', {})

        if not isinstance(event_type, str) or not event_type:
            logger.warning("Dropping host log with invalid event_type")
            return None
        if not isinstance(user, str) or not user:
            logger.warning("Dropping host log with invalid user")
            return None
        if not isinstance(action, str) or not action:
            logger.warning("Dropping host log with invalid action")
            return None
        if process_name is not None and not isinstance(process_name, str):
            logger.warning("Dropping host log with invalid process_name")
            return None
        if src_ip is not None and not isinstance(src_ip, str):
            logger.warning("Dropping host log with invalid src_ip")
            return None
        if not isinstance(details, dict):
            logger.warning("Dropping host log with invalid details payload")
            return None

        return IDSEvent.create_host_event(
            event_type=event_type,
            user=user,
            action=action,
            process_name=process_name,
            src_ip=src_ip,
            details=details
        )

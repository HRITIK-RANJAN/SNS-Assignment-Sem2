import logging
import multiprocessing
from typing import Dict, Any
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
                self.output_queue.put(event.to_json())
            except multiprocessing.queues.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing host log: {e}")
        logger.info("HostSensor stopped.")

    def stop(self):
        self.running = False

    def _process_log(self, raw_log: Dict[str, Any]) -> IDSEvent:
        # Expected keys: 'event_type', 'user', 'action', 'process_name', 'src_ip', 'details'
        return IDSEvent.create_host_event(
            event_type=raw_log.get('event_type', 'unknown'),
            user=raw_log.get('user', 'unknown'),
            action=raw_log.get('action', 'unknown'),
            process_name=raw_log.get('process_name'),
            src_ip=raw_log.get('src_ip'),
            details=raw_log.get('details', {})
        )

import logging
import multiprocessing
from typing import Dict, Any
from schemas import IDSEvent

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NetworkSensor")

class NetworkSensor:
    def __init__(self, input_queue: multiprocessing.Queue, output_queue: multiprocessing.Queue):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.running = False

    def start(self):
        self.running = True
        logger.info("NetworkSensor started.")
        while self.running:
            try:
                # input_queue contains raw flow dictionaries simulating raw packets/flows
                raw_flow: Dict[str, Any] = self.input_queue.get(timeout=1.0)
                if raw_flow is None: # poison pill to stop
                    break
                event = self._process_flow(raw_flow)
                self.output_queue.put(event.to_json())
            except multiprocessing.queues.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing flow: {e}")
        logger.info("NetworkSensor stopped.")

    def stop(self):
        self.running = False

    def _process_flow(self, raw_flow: Dict[str, Any]) -> IDSEvent:
        return IDSEvent.create_network_event(
            event_type='connection',
            src_ip=raw_flow.get('src_ip', '0.0.0.0'),
            dst_ip=raw_flow.get('dst_ip', '0.0.0.0'),
            src_port=raw_flow.get('src_port', 0),
            dst_port=raw_flow.get('dst_port', 0),
            protocol=raw_flow.get('protocol', 'TCP'),
            packet_count=raw_flow.get('packet_count', 1),
            byte_count=raw_flow.get('byte_count', 0)
        )

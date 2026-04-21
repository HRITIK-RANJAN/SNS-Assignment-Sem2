import logging
import multiprocessing
from typing import Dict, Any, Optional
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
                if event is not None:
                    self.output_queue.put(event.to_json())
            except multiprocessing.queues.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing flow: {e}")
        logger.info("NetworkSensor stopped.")

    def stop(self):
        self.running = False

    def _process_flow(self, raw_flow: Dict[str, Any]) -> Optional[IDSEvent]:
        required = ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol')
        missing = [k for k in required if k not in raw_flow]
        if missing:
            logger.warning(f"Dropping malformed network flow. Missing keys: {missing}")
            return None

        src_ip = raw_flow.get('src_ip')
        dst_ip = raw_flow.get('dst_ip')
        src_port = raw_flow.get('src_port')
        dst_port = raw_flow.get('dst_port')
        protocol = raw_flow.get('protocol')
        packet_count = raw_flow.get('packet_count', 1)
        byte_count = raw_flow.get('byte_count', 0)

        if not isinstance(src_ip, str) or not src_ip:
            logger.warning("Dropping network flow with invalid src_ip")
            return None
        if not isinstance(dst_ip, str) or not dst_ip:
            logger.warning("Dropping network flow with invalid dst_ip")
            return None
        if not isinstance(src_port, int) or not isinstance(dst_port, int):
            logger.warning("Dropping network flow with invalid ports")
            return None
        if not isinstance(protocol, str) or not protocol:
            logger.warning("Dropping network flow with invalid protocol")
            return None
        if not isinstance(packet_count, int) or packet_count < 1:
            logger.warning("Dropping network flow with invalid packet_count")
            return None
        if not isinstance(byte_count, int) or byte_count < 0:
            logger.warning("Dropping network flow with invalid byte_count")
            return None

        return IDSEvent.create_network_event(
            event_type='connection',
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=byte_count
        )

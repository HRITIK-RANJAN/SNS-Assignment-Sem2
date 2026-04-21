import logging
import multiprocessing
import time
import random
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Simulator")

class Simulator:
    def __init__(self, net_q: multiprocessing.Queue, host_q: multiprocessing.Queue):
        self.net_q = net_q
        self.host_q = host_q

    def generate_benign(self, duration: int, rate: float = 1.0):
        """Generates random benign traffic and host logs"""
        logger.info(f"Generating benign activity for {duration} seconds...")
        start_time = time.time()
        while time.time() - start_time < duration:
            # Random valid IPs
            ip = f"192.168.1.{random.randint(10, 50)}"
            port = random.choice([80, 443, 22, 53])
            
            # network connection
            self.net_q.put({
                'src_ip': ip,
                'dst_ip': '10.0.0.1',
                'src_port': random.randint(1024, 65535),
                'dst_port': port,
                'protocol': 'TCP'
            })
            
            # occasional host log
            if random.random() < 0.2:
                self.host_q.put({
                    'event_type': 'login',
                    'user': 'alice',
                    'action': 'success',
                    'src_ip': ip,
                })
            time.sleep(1 / rate)

    def scenario_brute_force(self):
        """Simulate brute force attack logic"""
        logger.info("Starting brute force attack scenario...")
        ip = "192.168.1.100"
        for i in range(10):
            # network connect
            self.net_q.put({
                'src_ip': ip,
                'dst_ip': '10.0.0.1',
                'src_port': random.randint(1024, 65535),
                'dst_port': 22,
                'protocol': 'TCP'
            })
            # failed host log
            self.host_q.put({
                'event_type': 'login',
                'user': 'root',
                'action': 'failed',
                'src_ip': ip
            })
            time.sleep(0.1)

    def scenario_fast_port_scan(self):
        """Simulate fast port scanning"""
        logger.info("Starting fast port scan scenario...")
        ip = "192.168.1.101"
        for port in range(1, 30):
            self.net_q.put({
                'src_ip': ip,
                'dst_ip': '10.0.0.1',
                'src_port': random.randint(1024, 65535),
                'dst_port': port,
                'protocol': 'TCP'
            })
            time.sleep(0.05)
            
    def scenario_slow_port_scan(self):
        """Simulate slow port scanning"""
        logger.info("Starting slow port scan scenario...")
        ip = "192.168.1.102"
        for port in range(1, 30):
            self.net_q.put({
                'src_ip': ip,
                'dst_ip': '10.0.0.1',
                'src_port': random.randint(1024, 65535),
                'dst_port': port,
                'protocol': 'TCP'
            })
            time.sleep(0.5)

    def scenario_noise_injection(self):
        """Injecting identical noise events to trigger the replay attack rule"""
        logger.info("Starting noise injection (replay)...")
        ip = "192.168.1.103"
        for i in range(25):
            self.net_q.put({
                'src_ip': ip,
                'dst_ip': '10.0.0.1',
                'src_port': 1234,
                'dst_port': 5678,
                'protocol': 'UDP'
            })
            time.sleep(0.01)

    def scenario_sensor_failure(self):
        """Simulate sensor failure by sending only host logs for an attack"""
        logger.info("Starting sensor failure scenario (no network events for brute force)...")
        ip = "192.168.1.104"
        for i in range(10):
            # NO network events sent
            self.host_q.put({
                'event_type': 'login',
                'user': 'admin',
                'action': 'failed',
                'src_ip': ip
            })
            time.sleep(0.1)

    def scenario_multi_step_attack(self):
        """Brute force -> success -> suspicious process"""
        logger.info("Starting multi-step attack scenario...")
        ip = "192.168.1.105"
        user = "root"
        # 1. Provide a couple of network context events first
        self.net_q.put({
            'src_ip': ip,
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': 22,
            'protocol': 'TCP'
        })
        time.sleep(0.1)
        # 2. Brute force fail
        for i in range(5):
             self.host_q.put({
                'event_type': 'login',
                'user': user,
                'action': 'failed',
                'src_ip': ip
            })
             time.sleep(0.1)
        # 3. Success
        self.host_q.put({
                'event_type': 'login',
                'user': user,
                'action': 'success',
                'src_ip': ip
            })
        time.sleep(0.5)
        # 4. Suspicious process
        self.host_q.put({
                'event_type': 'process',
                'user': user,
                'action': 'executed',
                'process_name': 'cmd.exe',
                'src_ip': ip
            })

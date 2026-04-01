import time
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List

@dataclass
class IDSEvent:
    event_id: str
    timestamp: float
    sensor: str  # 'network' or 'host'
    event_type: str  # e.g., 'connection', 'login_attempt', 'process_creation'
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    packet_count: Optional[int] = None
    byte_count: Optional[int] = None
    user: Optional[str] = None
    action: Optional[str] = None  # e.g., 'failed', 'success', 'executed'
    process_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_dict(cls, data: dict) -> 'IDSEvent':
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> 'IDSEvent':
        return cls.from_dict(json.loads(json_str))

    @staticmethod
    def create_network_event(event_type: str, src_ip: str, dst_ip: str,
                             src_port: int, dst_port: int, protocol: str,
                             packet_count: int = 1, byte_count: int = 0) -> 'IDSEvent':
        return IDSEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            sensor='network',
            event_type=event_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=byte_count
        )

    @staticmethod
    def create_host_event(event_type: str, user: str, action: str,
                          process_name: Optional[str] = None,
                          src_ip: Optional[str] = None,
                          details: Optional[Dict[str, Any]] = None) -> 'IDSEvent':
        return IDSEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            sensor='host',
            event_type=event_type,
            user=user,
            action=action,
            process_name=process_name,
            src_ip=src_ip,
            details=details or {}
        )


@dataclass
class Alert:
    alert_id: str
    timestamp: float
    severity: str  # 'Info', 'Low', 'Medium', 'High', 'Critical'
    description: str
    source_events: List[str]   # List of event_ids
    rule_name: str
    sensors_involved: List[str]  # e.g., ['network', 'host']

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    # FIX: Alert was missing from_dict and from_json, forcing alert_manager.py
    # to use a fragile hasattr + dict-unpack fallback.  Both methods are now
    # defined here, mirroring the identical pattern on IDSEvent.
    @classmethod
    def from_dict(cls, data: dict) -> 'Alert':
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> 'Alert':
        return cls.from_dict(json.loads(json_str))
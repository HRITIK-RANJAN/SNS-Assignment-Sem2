import time
import json
import uuid
from dataclasses import dataclass, field, asdict, fields
from typing import Optional, Dict, Any, List

ALLOWED_SENSORS = {'network', 'host'}
ALLOWED_SEVERITIES = {'Info', 'Low', 'Medium', 'High', 'Critical'}

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
        if not isinstance(data, dict):
            raise ValueError("IDSEvent payload must be a dict")

        allowed_fields = {f.name for f in fields(cls)}
        unknown_fields = set(data.keys()) - allowed_fields
        if unknown_fields:
            raise ValueError(f"Unknown IDSEvent fields: {sorted(unknown_fields)}")

        required = ('event_id', 'timestamp', 'sensor', 'event_type')
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"Missing required IDSEvent fields: {missing}")

        normalized = dict(data)
        if not isinstance(normalized['event_id'], str) or not normalized['event_id']:
            raise ValueError("IDSEvent.event_id must be a non-empty string")

        if not isinstance(normalized['timestamp'], (int, float)):
            raise ValueError("IDSEvent.timestamp must be numeric")
        normalized['timestamp'] = float(normalized['timestamp'])

        if normalized['sensor'] not in ALLOWED_SENSORS:
            raise ValueError(f"IDSEvent.sensor must be one of {sorted(ALLOWED_SENSORS)}")

        if not isinstance(normalized['event_type'], str) or not normalized['event_type']:
            raise ValueError("IDSEvent.event_type must be a non-empty string")

        for key in ('src_ip', 'dst_ip', 'protocol', 'user', 'action', 'process_name'):
            if key in normalized and normalized[key] is not None and not isinstance(normalized[key], str):
                raise ValueError(f"IDSEvent.{key} must be a string or null")

        for key in ('src_port', 'dst_port', 'packet_count', 'byte_count'):
            if key in normalized and normalized[key] is not None and not isinstance(normalized[key], int):
                raise ValueError(f"IDSEvent.{key} must be an int or null")

        if 'details' in normalized and normalized['details'] is not None and not isinstance(normalized['details'], dict):
            raise ValueError("IDSEvent.details must be a dict or null")

        # Ensure strict sensor-specific core fields are present.
        if normalized['sensor'] == 'network':
            for key in ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'):
                if normalized.get(key) in (None, ''):
                    raise ValueError(f"Network event missing required field: {key}")
        if normalized['sensor'] == 'host':
            for key in ('user', 'action'):
                if normalized.get(key) in (None, ''):
                    raise ValueError(f"Host event missing required field: {key}")

        return cls(**normalized)

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
    src_ip: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    # FIX: Alert was missing from_dict and from_json, forcing alert_manager.py
    # to use a fragile hasattr + dict-unpack fallback.  Both methods are now
    # defined here, mirroring the identical pattern on IDSEvent.
    @classmethod
    def from_dict(cls, data: dict) -> 'Alert':
        if not isinstance(data, dict):
            raise ValueError("Alert payload must be a dict")

        allowed_fields = {f.name for f in fields(cls)}
        unknown_fields = set(data.keys()) - allowed_fields
        if unknown_fields:
            raise ValueError(f"Unknown Alert fields: {sorted(unknown_fields)}")

        required = (
            'alert_id', 'timestamp', 'severity', 'description',
            'source_events', 'rule_name', 'sensors_involved'
        )
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"Missing required Alert fields: {missing}")

        normalized = dict(data)
        if not isinstance(normalized['alert_id'], str) or not normalized['alert_id']:
            raise ValueError("Alert.alert_id must be a non-empty string")

        if not isinstance(normalized['timestamp'], (int, float)):
            raise ValueError("Alert.timestamp must be numeric")
        normalized['timestamp'] = float(normalized['timestamp'])

        if normalized['severity'] not in ALLOWED_SEVERITIES:
            raise ValueError(f"Alert.severity must be one of {sorted(ALLOWED_SEVERITIES)}")

        if not isinstance(normalized['description'], str) or not normalized['description']:
            raise ValueError("Alert.description must be a non-empty string")

        if not isinstance(normalized['rule_name'], str) or not normalized['rule_name']:
            raise ValueError("Alert.rule_name must be a non-empty string")

        if not isinstance(normalized['source_events'], list) or not all(isinstance(i, str) for i in normalized['source_events']):
            raise ValueError("Alert.source_events must be a list of strings")

        if not isinstance(normalized['sensors_involved'], list) or not all(
            isinstance(s, str) and s in ALLOWED_SENSORS for s in normalized['sensors_involved']
        ):
            raise ValueError("Alert.sensors_involved must contain valid sensor names")

        if 'src_ip' in normalized and normalized['src_ip'] is not None and not isinstance(normalized['src_ip'], str):
            raise ValueError("Alert.src_ip must be a string or null")

        return cls(**normalized)

    @classmethod
    def from_json(cls, json_str: str) -> 'Alert':
        return cls.from_dict(json.loads(json_str))
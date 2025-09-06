"""
BITS-SIEM Threat Detection Models
================================

Shared data models for threat detection to avoid circular imports.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional

@dataclass
class ThreatAlert:
    """Threat alert structure"""
    id: str
    tenant_id: str
    alert_type: str
    severity: str
    title: str
    description: str
    source_ip: str
    target_ip: Optional[str] = None
    timestamp: datetime = None
    risk_score: float = 0.0
    confidence: float = 0.0
    evidence: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    correlation_id: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.evidence is None:
            self.evidence = {}
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        if isinstance(data.get('timestamp'), datetime):
            data['timestamp'] = self.timestamp.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatAlert':
        """Create from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)

"""
BITS-SIEM Alert Management System
Handles alert generation, correlation, escalation, and notification
"""

import asyncio
import logging
import json
import uuid
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import structlog
import aioredis
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import config
from threat_models import ThreatAlert

logger = structlog.get_logger(__name__)

class AlertStatus(Enum):
    """Alert status enumeration"""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

class AlertSeverity(Enum):
    """Alert severity enumeration"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class AlertRule:
    """Alert rule configuration"""
    id: str
    name: str
    description: str
    enabled: bool
    conditions: Dict[str, Any]
    actions: List[str]
    severity: str
    cooldown_seconds: int = 300
    correlation_window: int = 900
    max_alerts_per_window: int = 5

@dataclass
class ManagedAlert:
    """Managed alert with lifecycle tracking"""
    id: str
    tenant_id: str
    threat_alert_id: str
    alert_type: str
    severity: str
    status: AlertStatus
    title: str
    description: str
    source_ip: str
    target_ip: Optional[str]
    created_at: datetime
    updated_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    acknowledged_by: Optional[str]
    resolved_by: Optional[str]
    risk_score: float
    confidence: float
    evidence: Dict[str, Any]
    metadata: Dict[str, Any]
    correlation_id: Optional[str]
    parent_alert_id: Optional[str]
    child_alert_ids: List[str]
    escalation_level: int = 0
    notification_count: int = 0
    last_notification_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.child_alert_ids is None:
            self.child_alert_ids = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        datetime_fields = ['created_at', 'updated_at', 'acknowledged_at', 'resolved_at', 'last_notification_at']
        for field in datetime_fields:
            if data.get(field) and isinstance(data[field], datetime):
                data[field] = data[field].isoformat()
        
        # Convert enum to string
        if isinstance(data.get('status'), AlertStatus):
            data['status'] = data['status'].value
        
        return data

# Database models
Base = declarative_base()

class AlertModel(Base):
    """SQLAlchemy model for managed alerts"""
    __tablename__ = 'alerts'
    
    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True, nullable=False)
    threat_alert_id = Column(String, index=True, nullable=False)
    alert_type = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    status = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    source_ip = Column(String, index=True, nullable=False)
    target_ip = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, index=True, nullable=False)
    updated_at = Column(DateTime, index=True, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String, nullable=True)
    resolved_by = Column(String, nullable=True)
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    evidence = Column(JSON, nullable=True)
    alert_metadata = Column("metadata", JSON, nullable=True)
    correlation_id = Column(String, index=True, nullable=True)
    parent_alert_id = Column(String, index=True, nullable=True)
    child_alert_ids = Column(JSON, nullable=True)
    escalation_level = Column(Integer, default=0)
    notification_count = Column(Integer, default=0)
    last_notification_at = Column(DateTime, nullable=True)

class AlertRuleModel(Base):
    """SQLAlchemy model for alert rules"""
    __tablename__ = 'alert_rules'
    
    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True)
    conditions = Column(JSON, nullable=False)
    actions = Column(JSON, nullable=False)
    severity = Column(String, nullable=False)
    cooldown_seconds = Column(Integer, default=300)
    correlation_window = Column(Integer, default=900)
    max_alerts_per_window = Column(Integer, default=5)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AlertCorrelationEngine:
    """Handles alert correlation and deduplication"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.correlation_window = config.alerts.correlation_window
        self.max_correlation_distance = config.alerts.max_correlation_distance
    
    async def correlate_alert(self, alert: ThreatAlert) -> Optional[str]:
        """Correlate new alert with existing ones"""
        try:
            # Get recent alerts for correlation
            correlation_key = f"correlation:{alert.tenant_id}:{alert.alert_type}"
            recent_alerts = await self.redis_client.lrange(correlation_key, 0, -1)
            
            # Find correlated alerts
            for alert_data in recent_alerts:
                existing_alert = json.loads(alert_data)
                
                # Check if alerts are similar enough to correlate
                if self._should_correlate(alert, existing_alert):
                    return existing_alert.get('correlation_id')
            
            # No correlation found, create new correlation ID
            correlation_id = str(uuid.uuid4())
            
            # Store alert for future correlation
            alert_data = {
                'id': alert.id,
                'correlation_id': correlation_id,
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip,
                'timestamp': alert.timestamp.isoformat(),
                'alert_type': alert.alert_type,
                'severity': alert.severity
            }
            
            await self.redis_client.lpush(correlation_key, json.dumps(alert_data))
            await self.redis_client.expire(correlation_key, self.correlation_window)
            
            return correlation_id
            
        except Exception as e:
            logger.error(f"Error correlating alert: {e}")
            return str(uuid.uuid4())  # Fallback to unique ID
    
    def _should_correlate(self, new_alert: ThreatAlert, existing_alert: Dict[str, Any]) -> bool:
        """Determine if two alerts should be correlated"""
        try:
            # Same alert type
            if new_alert.alert_type != existing_alert.get('alert_type'):
                return False
            
            # Same source IP
            if new_alert.source_ip != existing_alert.get('source_ip'):
                return False
            
            # Within time window
            existing_time = datetime.fromisoformat(existing_alert.get('timestamp'))
            time_diff = abs((new_alert.timestamp - existing_time).total_seconds())
            
            if time_diff > self.correlation_window:
                return False
            
            # Same target IP (if applicable)
            if new_alert.target_ip and existing_alert.get('target_ip'):
                if new_alert.target_ip != existing_alert.get('target_ip'):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error in correlation check: {e}")
            return False

class AlertNotificationService:
    """Handles alert notifications"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.notification_channels = config.alerts.notification_channels
        self.rate_limit_window = config.alerts.rate_limit_window
        self.max_notifications_per_window = config.alerts.max_notifications_per_window
    
    async def send_notification(self, alert: ManagedAlert) -> bool:
        """Send notification for alert"""
        try:
            # Check rate limits
            if not await self._check_rate_limit(alert):
                logger.warning(f"Rate limit exceeded for alert {alert.id}")
                return False
            
            # Prepare notification data (ensure no None values for Redis)
            metadata_dict = {
                'alert_type': str(alert.alert_type or ''),
                'risk_score': float(alert.risk_score or 0.0),
                'confidence': float(alert.confidence or 0.0),
                'correlation_id': str(alert.correlation_id or '')
            }
            
            notification_data = {
                'id': str(uuid.uuid4()),
                'tenant_id': str(alert.tenant_id or ''),
                'alert_id': str(alert.id or ''),
                'type': 'security_alert',
                'severity': str(alert.severity or 'info'),
                'title': str(alert.title or 'Security Alert'),
                'message': str(alert.description or 'Security alert detected'),
                'source_ip': str(alert.source_ip or ''),
                'target_ip': str(alert.target_ip or ''),
                'timestamp': str(alert.created_at.isoformat() if alert.created_at else datetime.utcnow().isoformat()),
                'metadata': json.dumps(metadata_dict)  # Convert to JSON string for Redis compatibility
            }
            
            # Send to notification queue
            notification_key = f"notifications:{alert.tenant_id}"
            await self.redis_client.lpush(notification_key, json.dumps(notification_data))
            
            # Send to real-time notification stream
            stream_key = f"notification_stream:{alert.tenant_id}"
            await self.redis_client.xadd(stream_key, notification_data)
            
            # Update rate limit tracking
            await self._update_rate_limit(alert)
            
            logger.info(f"Notification sent for alert {alert.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            return False
    
    async def _check_rate_limit(self, alert: ManagedAlert) -> bool:
        """Check if notification rate limit is exceeded"""
        try:
            rate_key = f"rate_limit:{alert.tenant_id}:{alert.alert_type}"
            current_count = await self.redis_client.get(rate_key)
            current_count = int(current_count) if current_count else 0
            
            return current_count < self.max_notifications_per_window
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True  # Allow on error
    
    async def _update_rate_limit(self, alert: ManagedAlert):
        """Update rate limit tracking"""
        try:
            rate_key = f"rate_limit:{alert.tenant_id}:{alert.alert_type}"
            await self.redis_client.incr(rate_key)
            await self.redis_client.expire(rate_key, self.rate_limit_window)
            
        except Exception as e:
            logger.error(f"Error updating rate limit: {e}")

class AlertManager:
    """Main alert management system"""
    
    def __init__(self):
        self.redis_client = None
        self.db_session = None
        self.correlation_engine = None
        self.notification_service = None
        self.alert_rules = {}
        self.stats = {
            'alerts_created': 0,
            'alerts_resolved': 0,
            'notifications_sent': 0,
            'correlations_found': 0,
            'start_time': datetime.utcnow()
        }
        
        # Initialize components
        self._init_database()
        # Redis initialization will be done asynchronously
        self.redis_client = None
        self.correlation_engine = None
        self.notification_service = None
    
    async def initialize(self):
        """Initialize async components"""
        await self._init_redis()
        self._init_services()
    
    def _init_database(self):
        """Initialize database connection"""
        try:
            engine = create_engine(config.database.url)
            Base.metadata.create_all(engine)
            SessionLocal = sessionmaker(bind=engine)
            self.db_session = SessionLocal()
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    async def _init_redis(self):
        """Initialize Redis connection"""
        try:
            redis_url = f"redis://{config.redis.host}:{config.redis.port}"
            if config.redis.password:
                self.redis_client = await aioredis.create_redis_pool(
                    redis_url,
                    password=config.redis.password,
                    db=config.redis.db
                )
            else:
                self.redis_client = await aioredis.create_redis_pool(
                    redis_url,
                    db=config.redis.db
                )
            
            # Test connection
            await self.redis_client.ping()
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
    
    def _init_services(self):
        """Initialize alert services"""
        if self.redis_client:
            self.correlation_engine = AlertCorrelationEngine(self.redis_client)
            self.notification_service = AlertNotificationService(self.redis_client)
    
    async def process_threat_alert(self, threat_alert: ThreatAlert) -> Optional[ManagedAlert]:
        """Process a threat alert and create managed alert"""
        try:
            # Check if alert should be suppressed
            # COMMENTED OUT FOR TESTING: Alert suppression disabled to verify detection
            # if await self._should_suppress_alert(threat_alert):
            #     logger.info(f"Alert suppressed: {threat_alert.id}")
            #     return None
            
            # Correlate with existing alerts
            correlation_id = None
            if self.correlation_engine:
                correlation_id = await self.correlation_engine.correlate_alert(threat_alert)
                if correlation_id != threat_alert.id:
                    self.stats['correlations_found'] += 1
            
            # Create managed alert
            managed_alert = ManagedAlert(
                id=str(uuid.uuid4()),
                tenant_id=threat_alert.tenant_id,
                threat_alert_id=threat_alert.id,
                alert_type=threat_alert.alert_type,
                severity=threat_alert.severity,
                status=AlertStatus.OPEN,
                title=threat_alert.title,
                description=threat_alert.description,
                source_ip=threat_alert.source_ip,
                target_ip=threat_alert.target_ip,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                acknowledged_at=None,
                resolved_at=None,
                acknowledged_by=None,
                resolved_by=None,
                risk_score=threat_alert.risk_score,
                confidence=threat_alert.confidence,
                evidence=threat_alert.evidence,
                metadata=threat_alert.metadata,
                correlation_id=correlation_id,
                parent_alert_id=None,
                child_alert_ids=[],
                escalation_level=0,
                notification_count=0
            )
            
            # Store in database
            await self._store_alert(managed_alert)
            
            # Send notification
            if self.notification_service:
                notification_sent = await self.notification_service.send_notification(managed_alert)
                if notification_sent:
                    managed_alert.notification_count += 1
                    managed_alert.last_notification_at = datetime.utcnow()
                    self.stats['notifications_sent'] += 1
            
            # Send enhanced notification to notification service
            await self._send_enhanced_notification(threat_alert, managed_alert)
            
            self.stats['alerts_created'] += 1
            logger.info(f"Alert created: {managed_alert.id}")
            
            return managed_alert
            
        except Exception as e:
            logger.error(f"Error processing threat alert: {e}")
            return None
    
    async def _should_suppress_alert(self, threat_alert: ThreatAlert) -> bool:
        """Check if alert should be suppressed based on rules"""
        try:
            # Check cooldown period
            cooldown_key = f"cooldown:{threat_alert.tenant_id}:{threat_alert.alert_type}:{threat_alert.source_ip}"
            cooldown_exists = await self.redis_client.exists(cooldown_key)
            
            if cooldown_exists:
                return True
            
            # Set cooldown
            await self.redis_client.setex(
                cooldown_key,
                config.alerts.default_cooldown,
                "1"
            )
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking alert suppression: {e}")
            return False
    
    async def _store_alert(self, alert: ManagedAlert):
        """Store alert in database using SecurityAlert model for API compatibility"""
        try:
            if self.db_session:
                # Import SecurityAlert from the API database module
                from sqlalchemy import Column, Integer, String, Text, Float, JSON, DateTime, ForeignKey
                from sqlalchemy.ext.declarative import declarative_base
                
                # Create SecurityAlert model compatible with API
                class SecurityAlert(Base):
                    __tablename__ = "security_alerts"
                    __table_args__ = {'extend_existing': True}
                    
                    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
                    tenant_id = Column(String, nullable=False)
                    alert_type = Column(String, nullable=False)
                    title = Column(String, nullable=False)
                    description = Column(Text)
                    severity = Column(String, nullable=False)
                    confidence_score = Column(Float, nullable=False)
                    username = Column(String, index=True)
                    source_ip = Column(String, index=True)
                    affected_systems = Column(JSON)
                    detection_rule_id = Column(Integer)
                    triggering_events = Column(JSON)
                    correlation_data = Column(JSON)
                    status = Column(String, default="open")
                    assigned_to = Column(String)
                    resolution_notes = Column(Text)
                    resolved_at = Column(DateTime)
                    created_at = Column(DateTime, default=datetime.utcnow, index=True)
                    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
                
                # Extract username from evidence if available
                username = None
                if alert.evidence and isinstance(alert.evidence, dict):
                    username = alert.evidence.get('username', '')
                
                # Create SecurityAlert record
                db_alert = SecurityAlert(
                    tenant_id=alert.tenant_id,
                    alert_type=alert.alert_type,
                    title=alert.title,
                    description=alert.description,
                    severity=alert.severity,
                    confidence_score=alert.confidence,
                    username=username,
                    source_ip=alert.source_ip,
                    affected_systems=[alert.source_ip] if alert.source_ip else [],
                    detection_rule_id=None,
                    triggering_events=[],
                    correlation_data=alert.metadata or {},
                    status="open",
                    created_at=alert.created_at,
                    updated_at=alert.updated_at
                )
                
                self.db_session.add(db_alert)
                self.db_session.commit()
                logger.info(f"Alert stored in security_alerts table: {alert.id}")
                
        except Exception as e:
            if self.db_session:
                self.db_session.rollback()
            logger.error(f"Error storing alert: {e}")
    
    async def _send_enhanced_notification(self, threat_alert: ThreatAlert, managed_alert: ManagedAlert):
        """Send enhanced notification to notification service"""
        try:
            if not self.redis_client:
                return
            
            # Prepare enhanced notification data (ensure no None values for Redis)
            notification_data = {
                'id': str(uuid.uuid4()),
                'tenant_id': str(threat_alert.tenant_id or ''),
                'user_id': 'system',  # Will be set by notification service based on tenant
                'type': 'security_alert',
                'severity': str(threat_alert.severity or 'info'),
                'title': str(threat_alert.title or 'Security Alert'),
                'message': str(threat_alert.description or 'Security alert detected'),
                'source_ip': str(threat_alert.source_ip or ''),
                'target_ip': str(threat_alert.target_ip or ''),
                'alert_id': str(managed_alert.id or ''),
                'correlation_id': str(managed_alert.correlation_id or ''),
                'metadata': {
                    'alert_type': str(threat_alert.alert_type or ''),
                    'risk_score': float(threat_alert.risk_score or 0.0),
                    'confidence_score': float(threat_alert.confidence or 0.0),
                    'failed_attempts': int(threat_alert.evidence.get('failed_attempts', 0)),
                    'time_window': int(threat_alert.evidence.get('window_seconds', 0)),
                    'ports_count': int(threat_alert.evidence.get('unique_ports', 0)),
                    'scan_type': str(threat_alert.evidence.get('scan_type', '')),
                    'username': str(threat_alert.evidence.get('username', '')),
                    'affected_systems': list(threat_alert.evidence.get('affected_systems', []))
                },
                'created_at': str(managed_alert.created_at.isoformat() if managed_alert.created_at else datetime.utcnow().isoformat())
            }
            
            # Convert metadata to JSON string for Redis compatibility
            notification_data['metadata'] = json.dumps(notification_data['metadata'])
            
            # Send to notification stream
            await self.redis_client.xadd('notification_stream', notification_data)
            
            logger.info(f"Enhanced notification sent for alert {managed_alert.id}")
            
        except Exception as e:
            logger.error(f"Error sending enhanced notification: {e}")
    
    async def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge an alert"""
        try:
            if self.db_session:
                alert = self.db_session.query(AlertModel).filter(
                    AlertModel.id == alert_id
                ).first()
                
                if alert:
                    alert.status = AlertStatus.ACKNOWLEDGED.value
                    alert.acknowledged_at = datetime.utcnow()
                    alert.acknowledged_by = user_id
                    alert.updated_at = datetime.utcnow()
                    
                    self.db_session.commit()
                    
                    logger.info(f"Alert acknowledged: {alert_id} by {user_id}")
                    return True
                    
            return False
            
        except Exception as e:
            if self.db_session:
                self.db_session.rollback()
            logger.error(f"Error acknowledging alert: {e}")
            return False
    
    async def resolve_alert(self, alert_id: str, user_id: str) -> bool:
        """Resolve an alert"""
        try:
            if self.db_session:
                alert = self.db_session.query(AlertModel).filter(
                    AlertModel.id == alert_id
                ).first()
                
                if alert:
                    alert.status = AlertStatus.RESOLVED.value
                    alert.resolved_at = datetime.utcnow()
                    alert.resolved_by = user_id
                    alert.updated_at = datetime.utcnow()
                    
                    self.db_session.commit()
                    
                    self.stats['alerts_resolved'] += 1
                    logger.info(f"Alert resolved: {alert_id} by {user_id}")
                    return True
                    
            return False
            
        except Exception as e:
            if self.db_session:
                self.db_session.rollback()
            logger.error(f"Error resolving alert: {e}")
            return False
    
    async def get_alerts(self, tenant_id: str, status: Optional[str] = None, 
                        limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts for a tenant"""
        try:
            if self.db_session:
                query = self.db_session.query(AlertModel).filter(
                    AlertModel.tenant_id == tenant_id
                )
                
                if status:
                    query = query.filter(AlertModel.status == status)
                
                alerts = query.order_by(AlertModel.created_at.desc()).limit(limit).all()
                
                return [
                    {
                        'id': alert.id,
                        'alert_type': alert.alert_type,
                        'severity': alert.severity,
                        'status': alert.status,
                        'title': alert.title,
                        'description': alert.description,
                        'source_ip': alert.source_ip,
                        'target_ip': alert.target_ip,
                        'created_at': alert.created_at.isoformat(),
                        'updated_at': alert.updated_at.isoformat(),
                        'risk_score': alert.risk_score,
                        'confidence': alert.confidence,
                        'correlation_id': alert.correlation_id,
                        'escalation_level': alert.escalation_level
                    }
                    for alert in alerts
                ]
                
            return []
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get alert manager statistics"""
        stats = self.stats.copy()
        stats['uptime_seconds'] = (datetime.utcnow() - stats['start_time']).total_seconds()
        stats['start_time'] = stats['start_time'].isoformat()
        return stats

# Global alert manager instance
alert_manager = AlertManager()

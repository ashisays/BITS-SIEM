#!/usr/bin/env python3
"""
BITS-SIEM Processing Service
Handles real-time analytics, threat detection, and ML-based analysis
"""

import asyncio
import json
import time
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from collections import defaultdict, deque
import pickle
import hashlib

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis
from kafka import KafkaConsumer, KafkaProducer
from loguru import logger
import psycopg2
from psycopg2.extras import RealDictCursor
import socketio
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
from celery import Celery
from celery.schedules import crontab

# Configure logging
logger.remove()
logger.add(
    "logs/processing.log",
    rotation="100 MB",
    retention="30 days",
    level="INFO",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)
logger.add(lambda msg: print(msg, end=""), level="INFO")

# Configuration
class Config:
    REDIS_HOST = "redis"
    REDIS_PORT = 6379
    KAFKA_BOOTSTRAP_SERVERS = "kafka:9092"
    DATABASE_URL = "postgresql://siem:siempassword@db:5432/siemdb"
    CELERY_BROKER_URL = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND = "redis://redis:6379/0"
    
    # Processing settings
    BATCH_SIZE = 100
    PROCESSING_INTERVAL = 5  # seconds
    ANOMALY_THRESHOLD = 0.8
    THREAT_SCORE_THRESHOLD = 0.7
    
    # ML model settings
    MODEL_UPDATE_INTERVAL = 3600  # 1 hour
    MIN_SAMPLES_FOR_TRAINING = 1000

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertType(Enum):
    ANOMALY = "anomaly"
    THREAT = "threat"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"
    SECURITY = "security"

@dataclass
class SecurityEvent:
    """Security event structure"""
    id: str
    timestamp: datetime
    tenant_id: str
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str = ""
    severity: str = "INFO"
    threat_level: ThreatLevel = ThreatLevel.LOW
    threat_score: float = 0.0
    description: str = ""
    raw_data: Dict[str, Any] = None
    indicators: List[str] = None
    tags: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": self.tenant_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "threat_level": self.threat_level.value,
            "threat_score": self.threat_score,
            "description": self.description,
            "raw_data": self.raw_data or {},
            "indicators": self.indicators or [],
            "tags": self.tags or []
        }

class ThreatPattern:
    """Threat pattern detection"""
    
    # Common attack patterns
    BRUTE_FORCE_PATTERNS = [
        r"Failed password for",
        r"Invalid password",
        r"Authentication failure",
        r"Login failed",
        r"Access denied"
    ]
    
    SQL_INJECTION_PATTERNS = [
        r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(from|into|where|table|database)\b)",
        r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*['\"])",
        r"(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(and|or)\b.*\b(1=1|1=0)\b)"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>"
    ]
    
    DOS_PATTERNS = [
        r"Connection rate limit exceeded",
        r"Too many requests",
        r"Rate limit exceeded",
        r"Connection flood",
        r"SYN flood"
    ]
    
    MALWARE_PATTERNS = [
        r"virus detected",
        r"malware found",
        r"trojan detected",
        r"spyware detected",
        r"ransomware detected"
    ]
    
    @classmethod
    def detect_threats(cls, message: str) -> List[Dict[str, Any]]:
        """Detect threats in a message"""
        threats = []
        message_lower = message.lower()
        
        # Check brute force patterns
        for pattern in cls.BRUTE_FORCE_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                threats.append({
                    "type": "brute_force",
                    "pattern": pattern,
                    "severity": "HIGH",
                    "description": "Potential brute force attack detected"
                })
        
        # Check SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                threats.append({
                    "type": "sql_injection",
                    "pattern": pattern,
                    "severity": "CRITICAL",
                    "description": "Potential SQL injection attempt detected"
                })
        
        # Check XSS patterns
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                threats.append({
                    "type": "xss",
                    "pattern": pattern,
                    "severity": "HIGH",
                    "description": "Potential XSS attack detected"
                })
        
        # Check DoS patterns
        for pattern in cls.DOS_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                threats.append({
                    "type": "dos",
                    "pattern": pattern,
                    "severity": "MEDIUM",
                    "description": "Potential DoS attack detected"
                })
        
        # Check malware patterns
        for pattern in cls.MALWARE_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                threats.append({
                    "type": "malware",
                    "pattern": pattern,
                    "severity": "CRITICAL",
                    "description": "Malware activity detected"
                })
        
        return threats

class AnomalyDetector:
    """Machine learning-based anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.training_data = []
        self.last_training = 0
        self.is_trained = False
    
    def extract_features(self, message: str, metadata: Dict[str, Any]) -> np.ndarray:
        """Extract features from a message"""
        features = []
        
        # Text-based features
        text_features = self.vectorizer.transform([message]).toarray()[0]
        features.extend(text_features)
        
        # Metadata features
        features.extend([
            metadata.get('hour', 0) / 24.0,  # Normalized hour
            metadata.get('day_of_week', 0) / 7.0,  # Normalized day
            metadata.get('message_length', 0) / 1000.0,  # Normalized length
            metadata.get('word_count', 0) / 100.0,  # Normalized word count
            metadata.get('special_char_ratio', 0),
            metadata.get('uppercase_ratio', 0),
            metadata.get('digit_ratio', 0)
        ])
        
        return np.array(features)
    
    def update_training_data(self, message: str, metadata: Dict[str, Any]):
        """Update training data with new message"""
        features = self.extract_features(message, metadata)
        self.training_data.append(features)
        
        # Keep only recent data
        if len(self.training_data) > 10000:
            self.training_data = self.training_data[-10000:]
    
    def train_model(self):
        """Train the anomaly detection model"""
        if len(self.training_data) < Config.MIN_SAMPLES_FOR_TRAINING:
            logger.warning(f"Not enough training data: {len(self.training_data)} < {Config.MIN_SAMPLES_FOR_TRAINING}")
            return
        
        try:
            # Convert to numpy array
            X = np.array(self.training_data)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train isolation forest
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.isolation_forest.fit(X_scaled)
            
            self.is_trained = True
            self.last_training = time.time()
            
            logger.info(f"Anomaly detection model trained with {len(self.training_data)} samples")
            
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {e}")
    
    def detect_anomaly(self, message: str, metadata: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if a message is anomalous"""
        if not self.is_trained or self.isolation_forest is None:
            return False, 0.0
        
        try:
            features = self.extract_features(message, metadata)
            features_scaled = self.scaler.transform([features])
            
            # Get anomaly score (lower = more anomalous)
            score = self.isolation_forest.score_samples(features_scaled)[0]
            
            # Convert to anomaly probability (higher = more anomalous)
            anomaly_prob = 1.0 - (score + 0.5)  # Normalize to [0, 1]
            
            is_anomalous = anomaly_prob > Config.ANOMALY_THRESHOLD
            
            return is_anomalous, anomaly_prob
            
        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            return False, 0.0

class ThreatIntelligence:
    """Threat intelligence and reputation checking"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.threat_indicators = set()
        self.reputation_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def load_threat_data(self):
        """Load threat intelligence data"""
        # In a real implementation, this would load from external sources
        # For now, we'll use some example data
        self.malicious_ips.update([
            "192.168.1.100",
            "10.0.0.50",
            "172.16.1.200"
        ])
        
        self.suspicious_domains.update([
            "malware.example.com",
            "phishing.evil.com",
            "botnet.net"
        ])
        
        self.threat_indicators.update([
            "cmd.exe",
            "powershell.exe",
            "wget",
            "curl",
            "nc ",
            "netcat"
        ])
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        if ip in self.reputation_cache:
            cached = self.reputation_cache[ip]
            if time.time() - cached['timestamp'] < self.cache_ttl:
                return cached['data']
        
        # Check against known malicious IPs
        is_malicious = ip in self.malicious_ips
        
        # In a real implementation, this would query external APIs
        reputation_data = {
            "ip": ip,
            "is_malicious": is_malicious,
            "reputation_score": 0.1 if is_malicious else 0.9,
            "categories": ["malware"] if is_malicious else [],
            "last_seen": datetime.now(timezone.utc).isoformat()
        }
        
        # Cache the result
        self.reputation_cache[ip] = {
            'data': reputation_data,
            'timestamp': time.time()
        }
        
        return reputation_data
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        is_suspicious = domain in self.suspicious_domains
        
        return {
            "domain": domain,
            "is_suspicious": is_suspicious,
            "reputation_score": 0.2 if is_suspicious else 0.8,
            "categories": ["phishing"] if is_suspicious else []
        }
    
    def check_indicators(self, message: str) -> List[str]:
        """Check for threat indicators in message"""
        found_indicators = []
        message_lower = message.lower()
        
        for indicator in self.threat_indicators:
            if indicator.lower() in message_lower:
                found_indicators.append(indicator)
        
        return found_indicators

class EventCorrelator:
    """Correlate events to detect complex threats"""
    
    def __init__(self):
        self.event_window = defaultdict(lambda: deque(maxlen=1000))
        self.correlation_rules = self._load_correlation_rules()
        self.correlated_events = []
    
    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        """Load correlation rules"""
        return [
            {
                "name": "brute_force_attack",
                "description": "Multiple failed login attempts from same IP",
                "conditions": [
                    {"field": "event_type", "value": "authentication_failure"},
                    {"field": "source_ip", "operator": "same"},
                    {"field": "count", "operator": ">=", "value": 5},
                    {"field": "time_window", "operator": "<=", "value": 300}  # 5 minutes
                ],
                "severity": "HIGH",
                "threat_level": ThreatLevel.HIGH
            },
            {
                "name": "port_scan",
                "description": "Multiple connection attempts to different ports",
                "conditions": [
                    {"field": "event_type", "value": "connection_attempt"},
                    {"field": "source_ip", "operator": "same"},
                    {"field": "destination_port", "operator": "different"},
                    {"field": "count", "operator": ">=", "value": 10},
                    {"field": "time_window", "operator": "<=", "value": 600}  # 10 minutes
                ],
                "severity": "MEDIUM",
                "threat_level": ThreatLevel.MEDIUM
            },
            {
                "name": "data_exfiltration",
                "description": "Large data transfer to external IP",
                "conditions": [
                    {"field": "event_type", "value": "data_transfer"},
                    {"field": "destination_ip", "operator": "external"},
                    {"field": "data_size", "operator": ">=", "value": 1000000},  # 1MB
                    {"field": "time_window", "operator": "<=", "value": 3600}  # 1 hour
                ],
                "severity": "CRITICAL",
                "threat_level": ThreatLevel.CRITICAL
            }
        ]
    
    def add_event(self, event: SecurityEvent):
        """Add event for correlation"""
        key = f"{event.tenant_id}:{event.source_ip}"
        self.event_window[key].append(event)
        
        # Check for correlations
        self._check_correlations(key)
    
    def _check_correlations(self, key: str):
        """Check for event correlations"""
        events = list(self.event_window[key])
        if len(events) < 2:
            return
        
        for rule in self.correlation_rules:
            if self._matches_rule(events, rule):
                self._create_correlated_event(events, rule)
    
    def _matches_rule(self, events: List[SecurityEvent], rule: Dict[str, Any]) -> bool:
        """Check if events match a correlation rule"""
        # Simplified rule matching - in a real implementation, this would be more sophisticated
        for condition in rule["conditions"]:
            if not self._check_condition(events, condition):
                return False
        return True
    
    def _check_condition(self, events: List[SecurityEvent], condition: Dict[str, Any]) -> bool:
        """Check if events match a condition"""
        field = condition["field"]
        operator = condition.get("operator", "equals")
        value = condition.get("value")
        
        if field == "count":
            return len(events) >= value
        elif field == "time_window":
            if len(events) < 2:
                return False
            time_diff = (events[-1].timestamp - events[0].timestamp).total_seconds()
            return time_diff <= value
        elif field == "event_type":
            return any(e.event_type == value for e in events)
        elif field == "source_ip":
            return len(set(e.source_ip for e in events)) == 1
        elif field == "destination_port":
            return len(set(getattr(e, 'destination_port', None) for e in events)) > 1
        
        return True
    
    def _create_correlated_event(self, events: List[SecurityEvent], rule: Dict[str, Any]):
        """Create a correlated event"""
        correlated_event = SecurityEvent(
            id=f"corr_{int(time.time())}",
            timestamp=datetime.now(timezone.utc),
            tenant_id=events[0].tenant_id,
            source_ip=events[0].source_ip,
            event_type=f"correlated_{rule['name']}",
            severity=rule["severity"],
            threat_level=rule["threat_level"],
            threat_score=0.9,
            description=rule["description"],
            raw_data={"rule": rule, "events": [e.to_dict() for e in events]},
            tags=["correlated", rule["name"]]
        )
        
        self.correlated_events.append(correlated_event)

class MessageProcessor:
    """Process syslog messages for threat detection"""
    
    def __init__(self):
        self.redis_client = None
        self.kafka_consumer = None
        self.kafka_producer = None
        self.db_connection = None
        self.anomaly_detector = AnomalyDetector()
        self.threat_intelligence = ThreatIntelligence()
        self.event_correlator = EventCorrelator()
        self.running = False
        
    async def initialize(self):
        """Initialize connections and components"""
        try:
            # Initialize Redis
            self.redis_client = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                decode_responses=True
            )
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
        
        try:
            # Initialize Kafka consumer
            self.kafka_consumer = KafkaConsumer(
                bootstrap_servers=Config.KAFKA_BOOTSTRAP_SERVERS,
                group_id='siem-processor',
                auto_offset_reset='latest',
                enable_auto_commit=True,
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
            
            # Subscribe to syslog topics
            self.kafka_consumer.subscribe(pattern='syslog.*')
            logger.info("Kafka consumer initialized")
        except Exception as e:
            logger.warning(f"Kafka consumer connection failed: {e}")
            self.kafka_consumer = None
        
        try:
            # Initialize Kafka producer
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=Config.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            logger.info("Kafka producer initialized")
        except Exception as e:
            logger.warning(f"Kafka producer connection failed: {e}")
            self.kafka_producer = None
        
        try:
            # Initialize database connection
            self.db_connection = psycopg2.connect(Config.DATABASE_URL)
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            self.db_connection = None
        
        # Load threat intelligence data
        self.threat_intelligence.load_threat_data()
        
        # Start processing
        self.running = True
        asyncio.create_task(self._process_messages())
        asyncio.create_task(self._periodic_training())
    
    async def _process_messages(self):
        """Process messages from Kafka"""
        if not self.kafka_consumer:
            logger.error("Kafka consumer not available")
            return
        
        try:
            for message in self.kafka_consumer:
                if not self.running:
                    break
                
                try:
                    await self._process_single_message(message.value)
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
        except Exception as e:
            logger.error(f"Error in message processing loop: {e}")
    
    async def _process_single_message(self, message_data: Dict[str, Any]):
        """Process a single syslog message"""
        try:
            # Extract message details
            message = message_data.get('message', '')
            source_ip = message_data.get('source_ip', '')
            tenant_id = message_data.get('tenant_id', 'unknown')
            timestamp = datetime.fromisoformat(message_data.get('timestamp', ''))
            
            # Extract metadata for anomaly detection
            metadata = {
                'hour': timestamp.hour,
                'day_of_week': timestamp.weekday(),
                'message_length': len(message),
                'word_count': len(message.split()),
                'special_char_ratio': len(re.findall(r'[^a-zA-Z0-9\s]', message)) / max(len(message), 1),
                'uppercase_ratio': len(re.findall(r'[A-Z]', message)) / max(len(message), 1),
                'digit_ratio': len(re.findall(r'\d', message)) / max(len(message), 1)
            }
            
            # Update anomaly detection training data
            self.anomaly_detector.update_training_data(message, metadata)
            
            # Detect threats
            threats = ThreatPattern.detect_threats(message)
            
            # Check for anomalies
            is_anomalous, anomaly_score = self.anomaly_detector.detect_anomaly(message, metadata)
            
            # Check threat intelligence
            ip_reputation = self.threat_intelligence.check_ip_reputation(source_ip)
            threat_indicators = self.threat_intelligence.check_indicators(message)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(
                threats, is_anomalous, anomaly_score, ip_reputation, threat_indicators
            )
            
            # Determine threat level
            threat_level = self._determine_threat_level(threat_score)
            
            # Create security event if significant
            if threat_score > Config.THREAT_SCORE_THRESHOLD or is_anomalous:
                security_event = SecurityEvent(
                    id=f"evt_{int(time.time())}_{hashlib.md5(message.encode()).hexdigest()[:8]}",
                    timestamp=timestamp,
                    tenant_id=tenant_id,
                    source_ip=source_ip,
                    event_type="syslog_analysis",
                    severity="HIGH" if threat_score > 0.7 else "MEDIUM",
                    threat_level=threat_level,
                    threat_score=threat_score,
                    description=self._generate_description(threats, is_anomalous, ip_reputation),
                    raw_data=message_data,
                    indicators=threat_indicators,
                    tags=self._generate_tags(threats, is_anomalous, ip_reputation)
                )
                
                # Add to correlation engine
                self.event_correlator.add_event(security_event)
                
                # Store and forward
                await self._store_security_event(security_event)
                
                # Send to notification service
                if self.kafka_producer:
                    self.kafka_producer.send(
                        'security-events',
                        value=security_event.to_dict()
                    )
                
                logger.info(f"Security event created: {security_event.id} (score: {threat_score:.2f})")
                
        except Exception as e:
            logger.error(f"Error processing single message: {e}")
    
    def _calculate_threat_score(self, threats: List[Dict], is_anomalous: bool, 
                               anomaly_score: float, ip_reputation: Dict, 
                               threat_indicators: List[str]) -> float:
        """Calculate overall threat score"""
        score = 0.0
        
        # Base score from pattern detection
        for threat in threats:
            if threat['severity'] == 'CRITICAL':
                score += 0.4
            elif threat['severity'] == 'HIGH':
                score += 0.3
            elif threat['severity'] == 'MEDIUM':
                score += 0.2
            else:
                score += 0.1
        
        # Anomaly score
        if is_anomalous:
            score += anomaly_score * 0.3
        
        # IP reputation score
        if ip_reputation.get('is_malicious'):
            score += 0.4
        
        # Threat indicators
        score += len(threat_indicators) * 0.1
        
        return min(score, 1.0)
    
    def _determine_threat_level(self, threat_score: float) -> ThreatLevel:
        """Determine threat level from score"""
        if threat_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif threat_score >= 0.6:
            return ThreatLevel.HIGH
        elif threat_score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _generate_description(self, threats: List[Dict], is_anomalous: bool, 
                            ip_reputation: Dict) -> str:
        """Generate event description"""
        descriptions = []
        
        if threats:
            threat_types = [t['type'] for t in threats]
            descriptions.append(f"Detected threats: {', '.join(threat_types)}")
        
        if is_anomalous:
            descriptions.append("Anomalous behavior detected")
        
        if ip_reputation.get('is_malicious'):
            descriptions.append("Source IP has malicious reputation")
        
        return "; ".join(descriptions) if descriptions else "Security event detected"
    
    def _generate_tags(self, threats: List[Dict], is_anomalous: bool, 
                      ip_reputation: Dict) -> List[str]:
        """Generate event tags"""
        tags = ["syslog", "automated_detection"]
        
        if threats:
            tags.extend([t['type'] for t in threats])
        
        if is_anomalous:
            tags.append("anomaly")
        
        if ip_reputation.get('is_malicious'):
            tags.append("malicious_ip")
        
        return tags
    
    async def _store_security_event(self, event: SecurityEvent):
        """Store security event in database"""
        if not self.db_connection:
            return
        
        try:
            with self.db_connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO security_events (
                        id, timestamp, tenant_id, source_ip, destination_ip,
                        event_type, severity, threat_level, threat_score,
                        description, raw_data, indicators, tags
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    event.id,
                    event.timestamp,
                    event.tenant_id,
                    event.source_ip,
                    event.destination_ip,
                    event.event_type,
                    event.severity,
                    event.threat_level.value,
                    event.threat_score,
                    event.description,
                    json.dumps(event.raw_data or {}),
                    json.dumps(event.indicators or []),
                    json.dumps(event.tags or [])
                ))
                self.db_connection.commit()
        except Exception as e:
            logger.error(f"Error storing security event: {e}")
            self.db_connection.rollback()
    
    async def _periodic_training(self):
        """Periodically retrain ML models"""
        while self.running:
            try:
                await asyncio.sleep(Config.MODEL_UPDATE_INTERVAL)
                self.anomaly_detector.train_model()
            except Exception as e:
                logger.error(f"Error in periodic training: {e}")

# FastAPI app for monitoring and management
app = FastAPI(title="BITS-SIEM Processing Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
processor = MessageProcessor()

class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    uptime: float
    models_trained: bool
    redis_connected: bool
    kafka_connected: bool
    database_connected: bool

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global processor
    
    logger.info("Starting BITS-SIEM Processing Service")
    await processor.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global processor
    
    logger.info("Shutting down BITS-SIEM Processing Service")
    processor.running = False
    
    if processor.kafka_consumer:
        processor.kafka_consumer.close()
    
    if processor.kafka_producer:
        processor.kafka_producer.close()
    
    if processor.db_connection:
        processor.db_connection.close()

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    uptime = time.time() - app.startup_time if hasattr(app, 'startup_time') else 0
    
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        uptime=uptime,
        models_trained=processor.anomaly_detector.is_trained,
        redis_connected=processor.redis_client is not None,
        kafka_connected=processor.kafka_consumer is not None,
        database_connected=processor.db_connection is not None
    )

@app.get("/stats")
async def get_stats():
    """Get processing statistics"""
    stats = {
        "anomaly_detector": {
            "is_trained": processor.anomaly_detector.is_trained,
            "training_samples": len(processor.anomaly_detector.training_data),
            "last_training": processor.anomaly_detector.last_training
        },
        "threat_intelligence": {
            "malicious_ips": len(processor.threat_intelligence.malicious_ips),
            "suspicious_domains": len(processor.threat_intelligence.suspicious_domains),
            "threat_indicators": len(processor.threat_intelligence.threat_indicators)
        },
        "event_correlator": {
            "correlated_events": len(processor.event_correlator.correlated_events),
            "active_windows": len(processor.event_correlator.event_window)
        }
    }
    return stats

@app.post("/train")
async def train_models():
    """Manually trigger model training"""
    processor.anomaly_detector.train_model()
    return {"message": "Model training completed"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8002,
        log_level="info",
        access_log=False
    ) 
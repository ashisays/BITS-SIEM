"""
BITS-SIEM Threat Detection Engines
Real-time threat detection with brute force and port scanning detection
"""

import asyncio
import logging
import json
import redis
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from collections import defaultdict
import structlog

from config import config
from stream_processor import ProcessedEvent

logger = structlog.get_logger(__name__)

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

class ThreatDetectionEngine(ABC):
    """Abstract base class for threat detection engines"""
    
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_errors': 0,
            'start_time': datetime.utcnow()
        }
    
    @abstractmethod
    async def analyze_event(self, event: ProcessedEvent) -> Optional[ThreatAlert]:
        """Analyze an event and return threat alert if detected"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Clean up old data and temporary storage"""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        stats = self.stats.copy()
        stats['uptime_seconds'] = (datetime.utcnow() - stats['start_time']).total_seconds()
        stats['start_time'] = stats['start_time'].isoformat()
        return stats

class BruteForceDetectionEngine(ThreatDetectionEngine):
    """Brute force attack detection engine"""
    
    def __init__(self):
        super().__init__("brute_force")
        self.redis_client = None
        self.threshold = config.threat_detection.brute_force_threshold
        self.window_seconds = config.threat_detection.brute_force_window
        self.enabled = config.threat_detection.brute_force_enabled
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection for state storage"""
        try:
            self.redis_client = redis.Redis(
                host=config.redis.host,
                port=config.redis.port,
                db=config.redis.db,
                password=config.redis.password,
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
        except Exception as e:
            logger.error(f"Failed to initialize Redis for brute force detection: {e}")
            self.enabled = False
    
    async def analyze_event(self, event: ProcessedEvent) -> Optional[ThreatAlert]:
        """Analyze event for brute force patterns"""
        if not self.enabled or not self.redis_client:
            return None
        
        try:
            self.stats['events_processed'] += 1
            
            # Only analyze authentication failure events
            if event.event_type != 'authentication_failure':
                return None
            
            # Key for tracking failed attempts by IP and tenant
            key = f"brute_force:{event.tenant_id}:{event.source_ip}"
            
            # Get current count
            current_count = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, key
            )
            current_count = int(current_count) if current_count else 0
            
            # Increment counter
            new_count = current_count + 1
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.setex, key, self.window_seconds, new_count
            )
            
            # Check if threshold is exceeded
            if new_count >= self.threshold:
                # Get additional context
                attempts_key = f"brute_force_attempts:{event.tenant_id}:{event.source_ip}"
                attempts = await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.lrange, attempts_key, 0, -1
                )
                
                # Store this attempt
                attempt_data = {
                    'timestamp': event.timestamp.isoformat(),
                    'message': event.message,
                    'program': event.raw_data.get('program', 'unknown')
                }
                
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.lpush, attempts_key, json.dumps(attempt_data)
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.expire, attempts_key, self.window_seconds
                )
                
                # Calculate confidence based on pattern
                confidence = min(new_count / (self.threshold * 2), 1.0)
                
                # Create threat alert
                alert = ThreatAlert(
                    id=f"brute_force_{event.tenant_id}_{event.source_ip}_{int(datetime.utcnow().timestamp())}",
                    tenant_id=event.tenant_id,
                    alert_type="brute_force_attack",
                    severity="critical",
                    title="Brute Force Attack Detected",
                    description=f"Detected {new_count} failed login attempts from {event.source_ip} within {self.window_seconds} seconds",
                    source_ip=event.source_ip,
                    risk_score=0.9,
                    confidence=confidence,
                    evidence={
                        'failed_attempts': new_count,
                        'threshold': self.threshold,
                        'window_seconds': self.window_seconds,
                        'recent_attempts': attempts[-5:] if attempts else []  # Last 5 attempts
                    },
                    metadata={
                        'detection_engine': self.name,
                        'first_seen': event.timestamp.isoformat(),
                        'last_seen': event.timestamp.isoformat()
                    }
                )
                
                self.stats['threats_detected'] += 1
                logger.warning(f"Brute force attack detected: {event.source_ip} -> {event.tenant_id}")
                
                return alert
            
            return None
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error in brute force detection: {e}")
            return None
    
    async def cleanup(self):
        """Clean up old Redis keys"""
        try:
            if self.redis_client:
                # Clean up old brute force tracking keys
                pattern = "brute_force:*"
                keys = self.redis_client.keys(pattern)
                
                for key in keys:
                    ttl = self.redis_client.ttl(key)
                    if ttl <= 0:  # Expired keys
                        self.redis_client.delete(key)
                
                # Clean up old attempts keys
                pattern = "brute_force_attempts:*"
                keys = self.redis_client.keys(pattern)
                
                for key in keys:
                    ttl = self.redis_client.ttl(key)
                    if ttl <= 0:  # Expired keys
                        self.redis_client.delete(key)
                        
        except Exception as e:
            logger.error(f"Error in brute force cleanup: {e}")

class PortScanDetectionEngine(ThreatDetectionEngine):
    """Port scanning detection engine"""
    
    def __init__(self):
        super().__init__("port_scan")
        self.redis_client = None
        self.threshold = config.threat_detection.port_scan_threshold
        self.window_seconds = config.threat_detection.port_scan_window
        self.enabled = config.threat_detection.port_scan_enabled
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection for state storage"""
        try:
            self.redis_client = redis.Redis(
                host=config.redis.host,
                port=config.redis.port,
                db=config.redis.db,
                password=config.redis.password,
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
        except Exception as e:
            logger.error(f"Failed to initialize Redis for port scan detection: {e}")
            self.enabled = False
    
    async def analyze_event(self, event: ProcessedEvent) -> Optional[ThreatAlert]:
        """Analyze event for port scanning patterns"""
        if not self.enabled or not self.redis_client:
            return None
        
        try:
            self.stats['events_processed'] += 1
            
            # Only analyze network connection events
            if event.event_type not in ['network_connection', 'security_event']:
                return None
            
            # Extract port information from message
            port = self._extract_port_from_event(event)
            if not port:
                return None
            
            # Key for tracking port access by IP and tenant
            key = f"port_scan:{event.tenant_id}:{event.source_ip}"
            
            # Add port to set and get count
            ports_count = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.sadd, key, port
            )
            
            # Set expiration
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.expire, key, self.window_seconds
            )
            
            # Get total unique ports accessed
            total_ports = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.scard, key
            )
            
            # Check if threshold is exceeded
            if total_ports >= self.threshold:
                # Get all ports accessed
                all_ports = await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.smembers, key
                )
                
                # Store scan details
                scan_key = f"port_scan_details:{event.tenant_id}:{event.source_ip}"
                scan_data = {
                    'timestamp': event.timestamp.isoformat(),
                    'port': port,
                    'message': event.message,
                    'program': event.raw_data.get('program', 'unknown')
                }
                
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.lpush, scan_key, json.dumps(scan_data)
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.expire, scan_key, self.window_seconds
                )
                
                # Calculate confidence based on pattern
                confidence = min(total_ports / (self.threshold * 2), 1.0)
                
                # Determine severity based on ports accessed
                severity = self._calculate_port_scan_severity(all_ports)
                
                # Create threat alert
                alert = ThreatAlert(
                    id=f"port_scan_{event.tenant_id}_{event.source_ip}_{int(datetime.utcnow().timestamp())}",
                    tenant_id=event.tenant_id,
                    alert_type="port_scan_attack",
                    severity=severity,
                    title="Port Scanning Activity Detected",
                    description=f"Detected connections to {total_ports} different ports from {event.source_ip} within {self.window_seconds} seconds",
                    source_ip=event.source_ip,
                    risk_score=0.7,
                    confidence=confidence,
                    evidence={
                        'unique_ports': total_ports,
                        'threshold': self.threshold,
                        'window_seconds': self.window_seconds,
                        'ports_accessed': sorted(list(all_ports), key=int)
                    },
                    metadata={
                        'detection_engine': self.name,
                        'scan_type': self._classify_scan_type(all_ports),
                        'first_seen': event.timestamp.isoformat(),
                        'last_seen': event.timestamp.isoformat()
                    }
                )
                
                self.stats['threats_detected'] += 1
                logger.warning(f"Port scan detected: {event.source_ip} -> {total_ports} ports")
                
                return alert
            
            return None
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error in port scan detection: {e}")
            return None
    
    def _extract_port_from_event(self, event: ProcessedEvent) -> Optional[str]:
        """Extract port number from event message"""
        try:
            message = event.message.lower()
            
            # Look for port patterns in the message
            import re
            
            # Pattern: "port 80", "port:80", "port=80"
            port_patterns = [
                r'port\s*[:=]?\s*(\d+)',
                r'dst\s*port\s*[:=]?\s*(\d+)',
                r'destination\s*port\s*[:=]?\s*(\d+)',
                r':(\d+)',  # Simple :port pattern
                r'service\s*[:=]?\s*(\d+)'
            ]
            
            for pattern in port_patterns:
                match = re.search(pattern, message)
                if match:
                    port = match.group(1)
                    if 1 <= int(port) <= 65535:
                        return port
            
            # Check if port is in enriched data
            if 'port' in event.raw_data:
                return str(event.raw_data['port'])
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting port from event: {e}")
            return None
    
    def _calculate_port_scan_severity(self, ports: Set[str]) -> str:
        """Calculate severity based on ports accessed"""
        try:
            port_numbers = [int(p) for p in ports]
            
            # Critical services
            critical_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
            admin_ports = {22, 3389, 5985, 5986}  # SSH, RDP, WinRM
            
            critical_count = len(set(port_numbers) & critical_ports)
            admin_count = len(set(port_numbers) & admin_ports)
            
            if admin_count >= 2:
                return "critical"
            elif critical_count >= 5:
                return "critical"
            elif len(port_numbers) >= 20:
                return "critical"
            elif len(port_numbers) >= 10:
                return "warning"
            else:
                return "info"
                
        except Exception:
            return "warning"
    
    def _classify_scan_type(self, ports: Set[str]) -> str:
        """Classify the type of port scan"""
        try:
            port_numbers = [int(p) for p in ports]
            
            # Check for common scan patterns
            if len(port_numbers) >= 50:
                return "comprehensive_scan"
            elif any(p in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995] for p in port_numbers):
                return "service_discovery"
            elif any(p in [22, 3389, 5985, 5986] for p in port_numbers):
                return "admin_service_scan"
            elif max(port_numbers) <= 1024:
                return "well_known_ports_scan"
            else:
                return "general_scan"
                
        except Exception:
            return "unknown_scan"
    
    async def cleanup(self):
        """Clean up old Redis keys"""
        try:
            if self.redis_client:
                # Clean up old port scan tracking keys
                pattern = "port_scan:*"
                keys = self.redis_client.keys(pattern)
                
                for key in keys:
                    ttl = self.redis_client.ttl(key)
                    if ttl <= 0:  # Expired keys
                        self.redis_client.delete(key)
                
                # Clean up old scan details keys
                pattern = "port_scan_details:*"
                keys = self.redis_client.keys(pattern)
                
                for key in keys:
                    ttl = self.redis_client.ttl(key)
                    if ttl <= 0:  # Expired keys
                        self.redis_client.delete(key)
                        
        except Exception as e:
            logger.error(f"Error in port scan cleanup: {e}")

class AnomalyDetectionEngine(ThreatDetectionEngine):
    """Machine learning-based anomaly detection engine"""
    
    def __init__(self):
        super().__init__("anomaly_detection")
        self.enabled = config.threat_detection.anomaly_detection_enabled
        self.threshold = config.ml.anomaly_threshold
        self.feature_window = config.ml.feature_window
        self.event_buffer = defaultdict(list)
        self.buffer_lock = asyncio.Lock()
    
    async def analyze_event(self, event: ProcessedEvent) -> Optional[ThreatAlert]:
        """Analyze event for anomalies using statistical methods"""
        if not self.enabled:
            return None
        
        try:
            self.stats['events_processed'] += 1
            
            # Buffer events for batch analysis
            async with self.buffer_lock:
                key = f"{event.tenant_id}:{event.source_ip}"
                self.event_buffer[key].append(event)
                
                # Keep only recent events
                cutoff_time = datetime.utcnow() - timedelta(seconds=self.feature_window)
                self.event_buffer[key] = [
                    e for e in self.event_buffer[key] 
                    if e.timestamp > cutoff_time
                ]
                
                # Analyze if we have enough events
                if len(self.event_buffer[key]) >= config.ml.min_samples:
                    return await self._analyze_anomalies(key, event)
            
            return None
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error in anomaly detection: {e}")
            return None
    
    async def _analyze_anomalies(self, key: str, latest_event: ProcessedEvent) -> Optional[ThreatAlert]:
        """Analyze events for anomalies"""
        try:
            events = self.event_buffer[key]
            
            # Extract features
            features = self._extract_features(events)
            
            # Calculate anomaly score using statistical methods
            anomaly_score = self._calculate_anomaly_score(features)
            
            if anomaly_score > self.threshold:
                # Create anomaly alert
                alert = ThreatAlert(
                    id=f"anomaly_{latest_event.tenant_id}_{latest_event.source_ip}_{int(datetime.utcnow().timestamp())}",
                    tenant_id=latest_event.tenant_id,
                    alert_type="anomaly_detected",
                    severity="warning",
                    title="Anomalous Behavior Detected",
                    description=f"Unusual activity pattern detected from {latest_event.source_ip}",
                    source_ip=latest_event.source_ip,
                    risk_score=anomaly_score,
                    confidence=anomaly_score,
                    evidence={
                        'anomaly_score': anomaly_score,
                        'threshold': self.threshold,
                        'events_analyzed': len(events),
                        'features': features
                    },
                    metadata={
                        'detection_engine': self.name,
                        'analysis_window': self.feature_window,
                        'first_seen': events[0].timestamp.isoformat(),
                        'last_seen': latest_event.timestamp.isoformat()
                    }
                )
                
                self.stats['threats_detected'] += 1
                logger.warning(f"Anomaly detected: {latest_event.source_ip} (score: {anomaly_score})")
                
                return alert
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing anomalies: {e}")
            return None
    
    def _extract_features(self, events: List[ProcessedEvent]) -> Dict[str, float]:
        """Extract features from events for anomaly detection"""
        try:
            features = {}
            
            # Event frequency
            features['event_frequency'] = len(events) / self.feature_window
            
            # Event type diversity
            event_types = set(e.event_type for e in events)
            features['event_type_diversity'] = len(event_types)
            
            # Average risk score
            risk_scores = [e.risk_score for e in events]
            features['avg_risk_score'] = sum(risk_scores) / len(risk_scores)
            
            # Time distribution (events per minute)
            time_buckets = defaultdict(int)
            for event in events:
                minute = event.timestamp.minute
                time_buckets[minute] += 1
            features['time_distribution_variance'] = self._calculate_variance(list(time_buckets.values()))
            
            # Failure rate (for authentication events)
            auth_events = [e for e in events if 'authentication' in e.event_type]
            if auth_events:
                failures = [e for e in auth_events if 'failure' in e.event_type]
                features['auth_failure_rate'] = len(failures) / len(auth_events)
            else:
                features['auth_failure_rate'] = 0.0
            
            # Program diversity
            programs = set(e.raw_data.get('program', 'unknown') for e in events)
            features['program_diversity'] = len(programs)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {}
    
    def _calculate_anomaly_score(self, features: Dict[str, float]) -> float:
        """Calculate anomaly score using statistical methods"""
        try:
            # Simple anomaly scoring based on feature thresholds
            score = 0.0
            
            # High event frequency
            if features.get('event_frequency', 0) > 5:  # >5 events per second
                score += 0.3
            
            # High event type diversity
            if features.get('event_type_diversity', 0) > 5:
                score += 0.2
            
            # High average risk score
            if features.get('avg_risk_score', 0) > 0.7:
                score += 0.3
            
            # High time distribution variance (burst activity)
            if features.get('time_distribution_variance', 0) > 10:
                score += 0.2
            
            # High authentication failure rate
            if features.get('auth_failure_rate', 0) > 0.5:
                score += 0.4
            
            # High program diversity
            if features.get('program_diversity', 0) > 10:
                score += 0.2
            
            return min(score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating anomaly score: {e}")
            return 0.0
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        if not values:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    async def cleanup(self):
        """Clean up old events from buffer"""
        try:
            async with self.buffer_lock:
                cutoff_time = datetime.utcnow() - timedelta(seconds=self.feature_window * 2)
                
                for key in list(self.event_buffer.keys()):
                    self.event_buffer[key] = [
                        e for e in self.event_buffer[key] 
                        if e.timestamp > cutoff_time
                    ]
                    
                    # Remove empty buffers
                    if not self.event_buffer[key]:
                        del self.event_buffer[key]
                        
        except Exception as e:
            logger.error(f"Error in anomaly detection cleanup: {e}")

class ThreatDetectionManager:
    """Manages all threat detection engines"""
    
    def __init__(self):
        self.engines = []
        self.running = False
        self.stats = {
            'start_time': None,
            'total_events_processed': 0,
            'total_threats_detected': 0,
            'engine_count': 0
        }
        
        # Initialize engines
        self._initialize_engines()
    
    def _initialize_engines(self):
        """Initialize all threat detection engines"""
        try:
            # Initialize enabled engines
            if config.threat_detection.brute_force_enabled:
                self.engines.append(BruteForceDetectionEngine())
            
            if config.threat_detection.port_scan_enabled:
                self.engines.append(PortScanDetectionEngine())
            
            if config.threat_detection.anomaly_detection_enabled:
                self.engines.append(AnomalyDetectionEngine())
            
            self.stats['engine_count'] = len(self.engines)
            
            logger.info(f"Initialized {len(self.engines)} threat detection engines")
            
        except Exception as e:
            logger.error(f"Error initializing threat detection engines: {e}")
    
    async def analyze_event(self, event: ProcessedEvent) -> List[ThreatAlert]:
        """Analyze event with all engines"""
        alerts = []
        
        try:
            self.stats['total_events_processed'] += 1
            
            # Run all engines in parallel
            tasks = []
            for engine in self.engines:
                if engine.enabled:
                    tasks.append(engine.analyze_event(event))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, ThreatAlert):
                        alerts.append(result)
                        self.stats['total_threats_detected'] += 1
                    elif isinstance(result, Exception):
                        logger.error(f"Engine error: {result}")
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error analyzing event: {e}")
            return alerts
    
    async def start_cleanup_task(self):
        """Start periodic cleanup task"""
        self.running = True
        
        while self.running:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Run cleanup on all engines
                for engine in self.engines:
                    try:
                        await engine.cleanup()
                    except Exception as e:
                        logger.error(f"Error in engine cleanup: {e}")
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    async def stop(self):
        """Stop the threat detection manager"""
        self.running = False
        
        # Final cleanup
        for engine in self.engines:
            try:
                await engine.cleanup()
            except Exception as e:
                logger.error(f"Error in final cleanup: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        stats = self.stats.copy()
        
        if stats['start_time']:
            stats['uptime_seconds'] = (datetime.utcnow() - stats['start_time']).total_seconds()
            stats['start_time'] = stats['start_time'].isoformat()
        
        # Add engine-specific stats
        stats['engines'] = {}
        for engine in self.engines:
            stats['engines'][engine.name] = engine.get_stats()
        
        return stats

# Global threat detection manager
threat_detector = ThreatDetectionManager()

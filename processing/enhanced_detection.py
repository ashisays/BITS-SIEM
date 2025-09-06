"""
BITS-SIEM Enhanced Detection Engine
==================================

This module provides enhanced detection capabilities with sophisticated
false positive reduction, including:

1. Adaptive Thresholds based on user behavior
2. Time-based Analysis (business hours, patterns)
3. Geographic Intelligence
4. Service Account Recognition
5. Legitimate Activity Patterns
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta, time
from dataclasses import dataclass, asdict
from collections import defaultdict
import statistics
from ipaddress import ip_address, ip_network, AddressValueError

# Import structlog conditionally
try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

# Import Redis conditionally
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    # Use mock Redis for testing
    try:
        from mock_redis import MockRedisModule
        redis = MockRedisModule()
        REDIS_AVAILABLE = True
        logger.warning("Using mock Redis for testing")
    except ImportError:
        redis = None

from config import config
from stream_processor import ProcessedEvent
from threat_models import ThreatAlert

# Logger is already initialized above

@dataclass
class AdaptiveThreshold:
    """Adaptive threshold configuration"""
    tenant_id: str
    user_identifier: str
    threshold_type: str  # brute_force, port_scan, anomaly
    base_threshold: int
    adaptive_threshold: int
    confidence: float
    last_updated: datetime
    sample_size: int
    false_positive_rate: float
    
class EnhancedBruteForceDetection:
    """Enhanced brute force detection with adaptive thresholds"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.threshold_key_prefix = "adaptive_threshold"
        self.min_samples = 20
        self.adaptation_factor = 0.1
    
    async def get_adaptive_threshold(self, tenant_id: str, user_identifier: str) -> int:
        """Get adaptive threshold for user"""
        try:
            key = f"{self.threshold_key_prefix}:brute_force:{tenant_id}:{user_identifier}"
            threshold_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, key
            )
            
            if threshold_data:
                data = json.loads(threshold_data)
                threshold = AdaptiveThreshold(**data)
                threshold.last_updated = datetime.fromisoformat(data['last_updated'])
                
                # Return adaptive threshold if confidence is high enough
                if threshold.confidence > 0.7:
                    return threshold.adaptive_threshold
            
            # Return base threshold if no adaptive data
            return config.threat_detection.brute_force_threshold
            
        except Exception as e:
            logger.error(f"Error getting adaptive threshold: {e}")
            return config.threat_detection.brute_force_threshold
    
    async def update_threshold_feedback(self, tenant_id: str, user_identifier: str, 
                                      was_false_positive: bool, original_threshold: int):
        """Update adaptive threshold based on feedback"""
        try:
            key = f"{self.threshold_key_prefix}:brute_force:{tenant_id}:{user_identifier}"
            threshold_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, key
            )
            
            if threshold_data:
                data = json.loads(threshold_data)
                threshold = AdaptiveThreshold(**data)
                threshold.last_updated = datetime.fromisoformat(data['last_updated'])
            else:
                # Create new threshold
                threshold = AdaptiveThreshold(
                    tenant_id=tenant_id,
                    user_identifier=user_identifier,
                    threshold_type='brute_force',
                    base_threshold=config.threat_detection.brute_force_threshold,
                    adaptive_threshold=config.threat_detection.brute_force_threshold,
                    confidence=0.5,
                    last_updated=datetime.utcnow(),
                    sample_size=0,
                    false_positive_rate=0.0
                )
            
            # Update based on feedback
            threshold.sample_size += 1
            
            if was_false_positive:
                # Increase threshold to reduce false positives
                threshold.adaptive_threshold = min(
                    threshold.adaptive_threshold + 1,
                    threshold.base_threshold * 3  # Cap at 3x base threshold
                )
                threshold.false_positive_rate = (
                    (threshold.false_positive_rate * (threshold.sample_size - 1) + 1) / threshold.sample_size
                )
            else:
                # Decrease threshold slightly for better detection
                threshold.adaptive_threshold = max(
                    threshold.adaptive_threshold - self.adaptation_factor,
                    threshold.base_threshold * 0.5  # Don't go below 50% of base
                )
            
            # Update confidence based on sample size
            threshold.confidence = min(1.0, threshold.sample_size / 50.0)
            threshold.last_updated = datetime.utcnow()
            
            # Store updated threshold
            threshold_dict = asdict(threshold)
            threshold_dict['last_updated'] = threshold.last_updated.isoformat()
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.setex, key, 86400 * 7, json.dumps(threshold_dict)  # 7 days
            )
            
            logger.info(f"Updated adaptive threshold for {user_identifier}: {threshold.adaptive_threshold}")
            
        except Exception as e:
            logger.error(f"Error updating threshold feedback: {e}")

class TimeBasedAnalysis:
    """Time-based analysis for detecting patterns and anomalies"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.pattern_key_prefix = "time_pattern"
    
    async def analyze_temporal_pattern(self, tenant_id: str, source_ip: str, 
                                     event_times: List[datetime]) -> Dict[str, Any]:
        """Analyze temporal patterns in events"""
        try:
            if len(event_times) < 3:
                return {'pattern_type': 'insufficient_data', 'confidence': 0.0}
            
            # Sort times
            sorted_times = sorted(event_times)
            
            # Calculate intervals between events
            intervals = []
            for i in range(1, len(sorted_times)):
                interval = (sorted_times[i] - sorted_times[i-1]).total_seconds()
                intervals.append(interval)
            
            # Analyze patterns
            avg_interval = statistics.mean(intervals)
            interval_variance = statistics.variance(intervals) if len(intervals) > 1 else 0
            
            # Detect pattern types
            if interval_variance < 10:  # Very consistent timing
                if avg_interval < 5:
                    return {
                        'pattern_type': 'rapid_automated',
                        'confidence': 0.9,
                        'avg_interval': avg_interval,
                        'variance': interval_variance
                    }
                elif 30 <= avg_interval <= 120:
                    return {
                        'pattern_type': 'scripted_attack',
                        'confidence': 0.8,
                        'avg_interval': avg_interval,
                        'variance': interval_variance
                    }
            elif interval_variance > 100:  # Highly variable timing
                return {
                    'pattern_type': 'human_like',
                    'confidence': 0.7,
                    'avg_interval': avg_interval,
                    'variance': interval_variance
                }
            
            return {
                'pattern_type': 'mixed',
                'confidence': 0.5,
                'avg_interval': avg_interval,
                'variance': interval_variance
            }
            
        except Exception as e:
            logger.error(f"Error analyzing temporal pattern: {e}")
            return {'pattern_type': 'error', 'confidence': 0.0}
    
    async def is_business_hours_violation(self, tenant_id: str, timestamp: datetime) -> bool:
        """Check if event occurs during suspicious hours"""
        try:
            # Get business hours configuration (import here to avoid circular imports)
            try:
                from false_positive_reduction import fp_reduction_engine
                is_business_hours = await fp_reduction_engine.business_hours.is_business_hours(
                    tenant_id, timestamp
                )
            except ImportError:
                logger.warning("False positive reduction not available for business hours check")
                is_business_hours = True
            
            # Events outside business hours are more suspicious
            if not is_business_hours:
                # Check if it's a weekend or late night
                hour = timestamp.hour
                weekday = timestamp.weekday()
                
                # Very suspicious hours (2 AM - 5 AM)
                if 2 <= hour <= 5:
                    return True
                
                # Weekend activity might be suspicious for business tenants
                if weekday >= 5:  # Saturday or Sunday
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking business hours violation: {e}")
            return False

class GeographicIntelligence:
    """Geographic analysis for detecting suspicious locations"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.geo_key_prefix = "geo_intelligence"
        
        # High-risk countries (example list)
        self.high_risk_countries = {
            'CN', 'RU', 'KP', 'IR', 'PK'  # Add more as needed
        }
        
        # Known VPN/Proxy providers (example)
        self.known_vpn_ranges = [
            '185.220.100.0/22',  # Tor exit nodes (example)
            '198.98.50.0/24',    # VPN provider (example)
        ]
    
    async def analyze_geographic_risk(self, source_ip: str, country: str = None) -> Dict[str, Any]:
        """Analyze geographic risk factors"""
        try:
            risk_score = 0.0
            risk_factors = []
            
            # Check high-risk countries
            if country and country in self.high_risk_countries:
                risk_score += 0.3
                risk_factors.append(f"High-risk country: {country}")
            
            # Check for known VPN/Proxy ranges
            try:
                ip = ip_address(source_ip)
                for vpn_range in self.known_vpn_ranges:
                    if ip in ip_network(vpn_range):
                        risk_score += 0.4
                        risk_factors.append("Known VPN/Proxy range")
                        break
            except AddressValueError:
                pass
            
            # Check for geographic impossibility (rapid location changes)
            last_location = await self._get_last_location(source_ip)
            if last_location and country and last_location != country:
                time_diff = (datetime.utcnow() - last_location['timestamp']).total_seconds()
                if time_diff < 3600:  # Less than 1 hour
                    risk_score += 0.5
                    risk_factors.append("Rapid geographic change")
            
            # Store current location
            if country:
                await self._store_location(source_ip, country)
            
            return {
                'risk_score': min(risk_score, 1.0),
                'risk_factors': risk_factors,
                'country': country
            }
            
        except Exception as e:
            logger.error(f"Error analyzing geographic risk: {e}")
            return {'risk_score': 0.0, 'risk_factors': [], 'country': country}
    
    async def _get_last_location(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """Get last known location for IP"""
        try:
            key = f"{self.geo_key_prefix}:location:{source_ip}"
            location_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, key
            )
            
            if location_data:
                data = json.loads(location_data)
                data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                return data
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting last location: {e}")
            return None
    
    async def _store_location(self, source_ip: str, country: str):
        """Store current location for IP"""
        try:
            key = f"{self.geo_key_prefix}:location:{source_ip}"
            location_data = {
                'country': country,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.setex, key, 86400, json.dumps(location_data)  # 24 hours
            )
            
        except Exception as e:
            logger.error(f"Error storing location: {e}")

class ServiceAccountDetector:
    """Detects and handles service account activities"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.service_key_prefix = "service_account"
        
        # Service account indicators
        self.service_indicators = [
            'service', 'api', 'system', 'bot', 'monitor', 'backup',
            'jenkins', 'gitlab', 'github', 'ansible', 'puppet', 'chef',
            'nagios', 'zabbix', 'prometheus', 'grafana'
        ]
        
        # Service user agents
        self.service_user_agents = [
            'curl', 'wget', 'python-requests', 'java', 'go-http-client',
            'ansible', 'puppet', 'chef', 'nagios', 'zabbix'
        ]
    
    async def classify_account_type(self, username: str, user_agent: str = None, 
                                  source_ip: str = None) -> Dict[str, Any]:
        """Classify account as human, service, or system"""
        try:
            confidence = 0.0
            account_type = 'human'  # Default
            indicators = []
            
            # Check username patterns
            username_lower = username.lower()
            for indicator in self.service_indicators:
                if indicator in username_lower:
                    account_type = 'service_account'
                    confidence += 0.3
                    indicators.append(f"Username contains '{indicator}'")
                    break
            
            # Check user agent patterns
            if user_agent:
                user_agent_lower = user_agent.lower()
                for ua_indicator in self.service_user_agents:
                    if ua_indicator in user_agent_lower:
                        account_type = 'service_account'
                        confidence += 0.4
                        indicators.append(f"Service user agent: {ua_indicator}")
                        break
            
            # Check for consistent automated behavior
            if source_ip:
                behavior = await self._analyze_automated_behavior(username, source_ip)
                if behavior['is_automated']:
                    account_type = 'service_account'
                    confidence += 0.3
                    indicators.extend(behavior['indicators'])
            
            return {
                'account_type': account_type,
                'confidence': min(confidence, 1.0),
                'indicators': indicators
            }
            
        except Exception as e:
            logger.error(f"Error classifying account type: {e}")
            return {'account_type': 'human', 'confidence': 0.0, 'indicators': []}
    
    async def _analyze_automated_behavior(self, username: str, source_ip: str) -> Dict[str, Any]:
        """Analyze if behavior appears automated"""
        try:
            # This would analyze historical patterns
            # For now, return basic analysis
            return {
                'is_automated': False,
                'indicators': []
            }
            
        except Exception as e:
            logger.error(f"Error analyzing automated behavior: {e}")
            return {'is_automated': False, 'indicators': []}

class LegitimateActivityDetector:
    """Detects patterns of legitimate activity"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.activity_key_prefix = "legitimate_activity"
    
    async def is_legitimate_maintenance(self, tenant_id: str, source_ip: str, 
                                      event_type: str, timestamp: datetime) -> bool:
        """Check if activity appears to be legitimate maintenance"""
        try:
            # Check for maintenance windows
            maintenance_key = f"{self.activity_key_prefix}:maintenance:{tenant_id}"
            maintenance_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, maintenance_key
            )
            
            if maintenance_data:
                windows = json.loads(maintenance_data)
                for window in windows:
                    start = datetime.fromisoformat(window['start'])
                    end = datetime.fromisoformat(window['end'])
                    if start <= timestamp <= end:
                        # Check if IP is authorized for maintenance
                        if source_ip in window.get('authorized_ips', []):
                            return True
            
            # Check for known maintenance patterns
            if event_type == 'port_scan_attack':
                # Network discovery during maintenance hours
                if 2 <= timestamp.hour <= 6:  # Early morning maintenance
                    return await self._is_authorized_scanner(tenant_id, source_ip)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking legitimate maintenance: {e}")
            return False
    
    async def _is_authorized_scanner(self, tenant_id: str, source_ip: str) -> bool:
        """Check if IP is authorized for scanning"""
        try:
            # Check if IP is in authorized scanner list
            scanner_key = f"{self.activity_key_prefix}:authorized_scanners:{tenant_id}"
            is_authorized = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.sismember, scanner_key, source_ip
            )
            
            return bool(is_authorized)
            
        except Exception as e:
            logger.error(f"Error checking authorized scanner: {e}")
            return False
    
    async def add_maintenance_window(self, tenant_id: str, start_time: datetime, 
                                   end_time: datetime, authorized_ips: List[str], 
                                   description: str = ""):
        """Add maintenance window"""
        try:
            maintenance_key = f"{self.activity_key_prefix}:maintenance:{tenant_id}"
            
            # Get existing windows
            existing_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, maintenance_key
            )
            
            windows = json.loads(existing_data) if existing_data else []
            
            # Add new window
            new_window = {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'authorized_ips': authorized_ips,
                'description': description,
                'created_at': datetime.utcnow().isoformat()
            }
            
            windows.append(new_window)
            
            # Store updated windows
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.setex, maintenance_key, 86400 * 30, json.dumps(windows)  # 30 days
            )
            
            logger.info(f"Added maintenance window for tenant {tenant_id}: {start_time} - {end_time}")
            
        except Exception as e:
            logger.error(f"Error adding maintenance window: {e}")

class EnhancedDetectionEngine:
    """Main enhanced detection engine"""
    
    def __init__(self):
        self.redis_client = None
        self.enhanced_brute_force = None
        self.time_analysis = None
        self.geo_intelligence = None
        self.service_detector = None
        self.legitimate_detector = None
        self.enabled = True
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, enhanced detection disabled")
            self.enabled = False
            return
            
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
            
            # Initialize components
            self.enhanced_brute_force = EnhancedBruteForceDetection(self.redis_client)
            self.time_analysis = TimeBasedAnalysis(self.redis_client)
            self.geo_intelligence = GeographicIntelligence(self.redis_client)
            self.service_detector = ServiceAccountDetector(self.redis_client)
            self.legitimate_detector = LegitimateActivityDetector(self.redis_client)
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis for enhanced detection: {e}")
            self.enabled = False
    
    async def enhance_threat_analysis(self, event: ProcessedEvent, alert: ThreatAlert) -> Dict[str, Any]:
        """Perform enhanced analysis on threat alert"""
        if not self.enabled:
            return {'enhanced': False, 'reason': 'Enhanced detection disabled'}
        
        try:
            analysis = {
                'enhanced': True,
                'temporal_analysis': {},
                'geographic_analysis': {},
                'account_analysis': {},
                'legitimacy_check': {},
                'risk_adjustment': 0.0
            }
            
            # Temporal analysis
            if alert.alert_type in ['brute_force_attack', 'port_scan_attack']:
                # Analyze timing patterns (would need historical data)
                analysis['temporal_analysis'] = await self.time_analysis.analyze_temporal_pattern(
                    event.tenant_id, event.source_ip, [event.timestamp]
                )
                
                # Check business hours violation
                is_violation = await self.time_analysis.is_business_hours_violation(
                    event.tenant_id, event.timestamp
                )
                analysis['temporal_analysis']['business_hours_violation'] = is_violation
            
            # Geographic analysis
            country = event.raw_data.get('country')
            analysis['geographic_analysis'] = await self.geo_intelligence.analyze_geographic_risk(
                event.source_ip, country
            )
            
            # Account type analysis
            username = event.raw_data.get('username')
            user_agent = event.raw_data.get('user_agent')
            if username:
                analysis['account_analysis'] = await self.service_detector.classify_account_type(
                    username, user_agent, event.source_ip
                )
            
            # Legitimacy check
            is_legitimate = await self.legitimate_detector.is_legitimate_maintenance(
                event.tenant_id, event.source_ip, alert.alert_type, event.timestamp
            )
            analysis['legitimacy_check'] = {'is_legitimate_maintenance': is_legitimate}
            
            # Calculate risk adjustment
            risk_adjustment = 0.0
            
            # Reduce risk for service accounts
            if analysis['account_analysis'].get('account_type') == 'service_account':
                risk_adjustment -= 0.2
            
            # Increase risk for high-risk geography
            risk_adjustment += analysis['geographic_analysis'].get('risk_score', 0.0) * 0.3
            
            # Increase risk for business hours violations
            if analysis['temporal_analysis'].get('business_hours_violation'):
                risk_adjustment += 0.1
            
            # Reduce risk for legitimate maintenance
            if is_legitimate:
                risk_adjustment -= 0.5
            
            analysis['risk_adjustment'] = risk_adjustment
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in enhanced threat analysis: {e}")
            return {'enhanced': False, 'reason': f'Analysis error: {str(e)}'}

# Global enhanced detection engine
enhanced_detection_engine = EnhancedDetectionEngine()

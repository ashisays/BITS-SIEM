"""
BITS-SIEM False Positive Reduction Engine
========================================

This module implements sophisticated false positive reduction strategies for
brute force and port scanning detection, including:

1. Multi-tier Whitelisting (Static, Dynamic, Learning-based)
2. Behavioral Analysis (Time regularity, User patterns)
3. Context-Aware Rules (Business hours, Geographic considerations)
4. Service Account Recognition
5. Legitimate Activity Detection
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
class WhitelistEntry:
    """Whitelist entry configuration"""
    id: str
    tenant_id: str
    entry_type: str  # ip, network, user_agent, service_account
    value: str
    reason: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    confidence: float = 1.0
    auto_generated: bool = False
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class BusinessHoursConfig:
    """Business hours configuration for tenant"""
    tenant_id: str
    timezone: str
    weekday_start: time  # e.g., 08:00
    weekday_end: time    # e.g., 18:00
    weekend_start: Optional[time] = None
    weekend_end: Optional[time] = None
    holidays: List[str] = None  # ISO date strings
    maintenance_windows: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.holidays is None:
            self.holidays = []
        if self.maintenance_windows is None:
            self.maintenance_windows = []

@dataclass
class UserBehaviorProfile:
    """Enhanced user behavior profile"""
    tenant_id: str
    user_identifier: str  # username or service account
    profile_type: str  # human, service_account, system
    typical_hours: List[int]
    typical_days: List[int]
    typical_ips: Set[str]
    typical_user_agents: Set[str]
    avg_session_duration: float
    failure_tolerance: int  # acceptable failed attempts
    geographic_locations: Set[str]
    last_updated: datetime
    confidence_score: float
    sample_size: int
    
    def __post_init__(self):
        if isinstance(self.typical_ips, list):
            self.typical_ips = set(self.typical_ips)
        if isinstance(self.typical_user_agents, list):
            self.typical_user_agents = set(self.typical_user_agents)
        if isinstance(self.geographic_locations, list):
            self.geographic_locations = set(self.geographic_locations)

class StaticWhitelistManager:
    """Manages static whitelist entries"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.whitelist_key_prefix = "static_whitelist"
    
    async def add_whitelist_entry(self, entry: WhitelistEntry) -> bool:
        """Add entry to static whitelist"""
        try:
            key = f"{self.whitelist_key_prefix}:{entry.tenant_id}:{entry.entry_type}"
            entry_data = asdict(entry)
            entry_data['created_at'] = entry.created_at.isoformat()
            if entry.expires_at:
                entry_data['expires_at'] = entry.expires_at.isoformat()
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hset, key, entry.value, json.dumps(entry_data)
            )
            
            # Set expiration if specified
            if entry.expires_at:
                ttl = int((entry.expires_at - datetime.utcnow()).total_seconds())
                if ttl > 0:
                    await asyncio.get_event_loop().run_in_executor(
                        None, self.redis_client.expire, key, ttl
                    )
            
            logger.info(f"Added static whitelist entry: {entry.entry_type}={entry.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding static whitelist entry: {e}")
            return False
    
    async def is_whitelisted(self, tenant_id: str, entry_type: str, value: str) -> Optional[WhitelistEntry]:
        """Check if value is in static whitelist"""
        try:
            key = f"{self.whitelist_key_prefix}:{tenant_id}:{entry_type}"
            entry_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hget, key, value
            )
            
            if entry_data:
                data = json.loads(entry_data)
                data['created_at'] = datetime.fromisoformat(data['created_at'])
                if data.get('expires_at'):
                    data['expires_at'] = datetime.fromisoformat(data['expires_at'])
                    # Check if expired
                    if data['expires_at'] < datetime.utcnow():
                        await self.remove_whitelist_entry(tenant_id, entry_type, value)
                        return None
                
                return WhitelistEntry(**data)
            
            # Check network ranges for IP addresses
            if entry_type == 'ip':
                return await self._check_ip_in_networks(tenant_id, value)
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking static whitelist: {e}")
            return None
    
    async def _check_ip_in_networks(self, tenant_id: str, ip_str: str) -> Optional[WhitelistEntry]:
        """Check if IP is in any whitelisted network ranges"""
        try:
            ip = ip_address(ip_str)
            key = f"{self.whitelist_key_prefix}:{tenant_id}:network"
            
            all_networks = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hgetall, key
            )
            
            for network_str, entry_data in all_networks.items():
                try:
                    network = ip_network(network_str, strict=False)
                    if ip in network:
                        data = json.loads(entry_data)
                        data['created_at'] = datetime.fromisoformat(data['created_at'])
                        if data.get('expires_at'):
                            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
                        return WhitelistEntry(**data)
                except (AddressValueError, ValueError):
                    continue
            
            return None
            
        except AddressValueError:
            return None
        except Exception as e:
            logger.error(f"Error checking IP in networks: {e}")
            return None
    
    async def remove_whitelist_entry(self, tenant_id: str, entry_type: str, value: str) -> bool:
        """Remove entry from static whitelist"""
        try:
            key = f"{self.whitelist_key_prefix}:{tenant_id}:{entry_type}"
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hdel, key, value
            )
            logger.info(f"Removed static whitelist entry: {entry_type}={value}")
            return True
            
        except Exception as e:
            logger.error(f"Error removing static whitelist entry: {e}")
            return False

class DynamicWhitelistManager:
    """Manages dynamic whitelist based on successful authentication patterns"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.dynamic_key_prefix = "dynamic_whitelist"
        self.success_threshold = 5  # Successful logins needed for dynamic whitelisting
        self.whitelist_duration = 86400  # 24 hours
    
    async def record_successful_auth(self, tenant_id: str, source_ip: str, username: str) -> bool:
        """Record successful authentication for dynamic whitelisting"""
        try:
            # Track successful authentications per IP
            ip_key = f"{self.dynamic_key_prefix}:success:{tenant_id}:{source_ip}"
            count = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.incr, ip_key
            )
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.expire, ip_key, self.whitelist_duration
            )
            
            # If threshold reached, add to dynamic whitelist
            if count >= self.success_threshold:
                await self._add_to_dynamic_whitelist(tenant_id, source_ip, username, count)
            
            return True
            
        except Exception as e:
            logger.error(f"Error recording successful auth: {e}")
            return False
    
    async def _add_to_dynamic_whitelist(self, tenant_id: str, source_ip: str, username: str, success_count: int):
        """Add IP to dynamic whitelist"""
        try:
            whitelist_key = f"{self.dynamic_key_prefix}:active:{tenant_id}"
            entry_data = {
                'ip': source_ip,
                'username': username,
                'success_count': success_count,
                'whitelisted_at': datetime.utcnow().isoformat(),
                'confidence': min(1.0, success_count / 10.0)
            }
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hset, whitelist_key, source_ip, json.dumps(entry_data)
            )
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.expire, whitelist_key, self.whitelist_duration
            )
            
            logger.info(f"Added IP {source_ip} to dynamic whitelist for tenant {tenant_id}")
            
        except Exception as e:
            logger.error(f"Error adding to dynamic whitelist: {e}")
    
    async def is_dynamically_whitelisted(self, tenant_id: str, source_ip: str) -> Optional[Dict[str, Any]]:
        """Check if IP is dynamically whitelisted"""
        try:
            whitelist_key = f"{self.dynamic_key_prefix}:active:{tenant_id}"
            entry_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.hget, whitelist_key, source_ip
            )
            
            if entry_data:
                return json.loads(entry_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking dynamic whitelist: {e}")
            return None

class BehavioralAnalysisEngine:
    """Analyzes user behavior patterns to reduce false positives"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.profile_key_prefix = "behavior_profile"
        self.learning_window = 30  # days
        self.min_samples = 10
    
    async def build_user_profile(self, tenant_id: str, user_identifier: str) -> Optional[UserBehaviorProfile]:
        """Build behavioral profile for user"""
        try:
            # Get historical events for user
            events = await self._get_user_events(tenant_id, user_identifier)
            
            if len(events) < self.min_samples:
                logger.warning(f"Insufficient data for user profile: {user_identifier}")
                return None
            
            # Analyze patterns
            hours = [event['hour'] for event in events]
            days = [event['day'] for event in events]
            ips = set(event['source_ip'] for event in events)
            user_agents = set(event.get('user_agent', '') for event in events if event.get('user_agent'))
            locations = set(event.get('country', '') for event in events if event.get('country'))
            
            # Calculate statistics
            typical_hours = list(set(hours))
            typical_days = list(set(days))
            
            # Determine profile type
            profile_type = self._determine_profile_type(events, user_identifier)
            
            # Calculate failure tolerance based on profile type
            failure_tolerance = self._calculate_failure_tolerance(profile_type, events)
            
            profile = UserBehaviorProfile(
                tenant_id=tenant_id,
                user_identifier=user_identifier,
                profile_type=profile_type,
                typical_hours=typical_hours,
                typical_days=typical_days,
                typical_ips=ips,
                typical_user_agents=user_agents,
                avg_session_duration=statistics.mean([e.get('duration', 3600) for e in events]),
                failure_tolerance=failure_tolerance,
                geographic_locations=locations,
                last_updated=datetime.utcnow(),
                confidence_score=min(1.0, len(events) / 100.0),
                sample_size=len(events)
            )
            
            # Store profile
            await self._store_user_profile(profile)
            
            return profile
            
        except Exception as e:
            logger.error(f"Error building user profile: {e}")
            return None
    
    async def _get_user_events(self, tenant_id: str, user_identifier: str) -> List[Dict[str, Any]]:
        """Get historical events for user (mock implementation)"""
        # In a real implementation, this would query the database
        # For now, return empty list
        return []
    
    def _determine_profile_type(self, events: List[Dict[str, Any]], user_identifier: str) -> str:
        """Determine if user is human, service account, or system"""
        # Service account indicators
        if any(keyword in user_identifier.lower() for keyword in ['service', 'api', 'system', 'bot', 'monitor']):
            return 'service_account'
        
        # Check for automated patterns
        user_agents = [e.get('user_agent', '') for e in events]
        if len(set(user_agents)) == 1 and any(keyword in user_agents[0].lower() for keyword in ['curl', 'wget', 'python', 'java']):
            return 'service_account'
        
        # Check for 24/7 activity pattern
        hours = [e['hour'] for e in events]
        if len(set(hours)) > 20:  # Active in most hours
            return 'system'
        
        return 'human'
    
    def _calculate_failure_tolerance(self, profile_type: str, events: List[Dict[str, Any]]) -> int:
        """Calculate acceptable failure threshold based on profile type"""
        if profile_type == 'service_account':
            return 2  # Service accounts should rarely fail
        elif profile_type == 'system':
            return 3  # System accounts might have occasional failures
        else:  # human
            # Calculate based on historical failure rate
            failures = [e for e in events if e.get('event_type') == 'login_failure']
            if failures:
                failure_rate = len(failures) / len(events)
                return max(3, int(failure_rate * 20))  # Allow some human error
            return 5  # Default for humans
    
    async def _store_user_profile(self, profile: UserBehaviorProfile):
        """Store user profile in Redis"""
        try:
            key = f"{self.profile_key_prefix}:{profile.tenant_id}:{profile.user_identifier}"
            profile_data = asdict(profile)
            profile_data['last_updated'] = profile.last_updated.isoformat()
            profile_data['typical_ips'] = list(profile.typical_ips)
            profile_data['typical_user_agents'] = list(profile.typical_user_agents)
            profile_data['geographic_locations'] = list(profile.geographic_locations)
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.set, key, json.dumps(profile_data)
            )
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.expire, key, 86400 * 7  # 7 days
            )
            
        except Exception as e:
            logger.error(f"Error storing user profile: {e}")
    
    async def get_user_profile(self, tenant_id: str, user_identifier: str) -> Optional[UserBehaviorProfile]:
        """Get user behavioral profile"""
        try:
            key = f"{self.profile_key_prefix}:{tenant_id}:{user_identifier}"
            profile_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, key
            )
            
            if profile_data:
                data = json.loads(profile_data)
                data['last_updated'] = datetime.fromisoformat(data['last_updated'])
                data['typical_ips'] = set(data['typical_ips'])
                data['typical_user_agents'] = set(data['typical_user_agents'])
                data['geographic_locations'] = set(data['geographic_locations'])
                return UserBehaviorProfile(**data)
            
            # Try to build profile if not exists
            return await self.build_user_profile(tenant_id, user_identifier)
            
        except Exception as e:
            logger.error(f"Error getting user profile: {e}")
            return None

class BusinessHoursManager:
    """Manages business hours and maintenance windows"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.config_key_prefix = "business_hours"
    
    async def set_business_hours(self, config: BusinessHoursConfig) -> bool:
        """Set business hours configuration for tenant"""
        try:
            key = f"{self.config_key_prefix}:{config.tenant_id}"
            config_data = asdict(config)
            config_data['weekday_start'] = config.weekday_start.isoformat()
            config_data['weekday_end'] = config.weekday_end.isoformat()
            if config.weekend_start:
                config_data['weekend_start'] = config.weekend_start.isoformat()
            if config.weekend_end:
                config_data['weekend_end'] = config.weekend_end.isoformat()
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.set, key, json.dumps(config_data)
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting business hours: {e}")
            return False
    
    async def is_business_hours(self, tenant_id: str, timestamp: datetime) -> bool:
        """Check if timestamp is within business hours"""
        try:
            key = f"{self.config_key_prefix}:{tenant_id}"
            config_data = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, key
            )
            
            if not config_data:
                return True  # Default to always business hours if not configured
            
            config = json.loads(config_data)
            
            # Check if it's a holiday
            date_str = timestamp.date().isoformat()
            if date_str in config.get('holidays', []):
                return False
            
            # Check maintenance windows
            for window in config.get('maintenance_windows', []):
                start = datetime.fromisoformat(window['start'])
                end = datetime.fromisoformat(window['end'])
                if start <= timestamp <= end:
                    return False
            
            # Check business hours
            current_time = timestamp.time()
            weekday = timestamp.weekday()  # 0=Monday, 6=Sunday
            
            if weekday < 5:  # Weekday
                start_time = time.fromisoformat(config['weekday_start'])
                end_time = time.fromisoformat(config['weekday_end'])
                return start_time <= current_time <= end_time
            else:  # Weekend
                if config.get('weekend_start') and config.get('weekend_end'):
                    start_time = time.fromisoformat(config['weekend_start'])
                    end_time = time.fromisoformat(config['weekend_end'])
                    return start_time <= current_time <= end_time
                return False  # No weekend hours configured
            
        except Exception as e:
            logger.error(f"Error checking business hours: {e}")
            return True  # Default to business hours on error

class FalsePositiveReductionEngine:
    """Main engine for false positive reduction"""
    
    def __init__(self):
        self.redis_client = None
        self.static_whitelist = None
        self.dynamic_whitelist = None
        self.behavioral_analysis = None
        self.business_hours = None
        self.enabled = True
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, false positive reduction disabled")
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
            
            # Initialize managers
            self.static_whitelist = StaticWhitelistManager(self.redis_client)
            self.dynamic_whitelist = DynamicWhitelistManager(self.redis_client)
            self.behavioral_analysis = BehavioralAnalysisEngine(self.redis_client)
            self.business_hours = BusinessHoursManager(self.redis_client)
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis for false positive reduction: {e}")
            self.enabled = False
    
    async def should_suppress_alert(self, event: ProcessedEvent, alert: ThreatAlert) -> Tuple[bool, str]:
        """
        Determine if alert should be suppressed due to false positive indicators
        Returns (should_suppress, reason)
        """
        if not self.enabled:
            return False, "FP reduction disabled"
        
        try:
            # Check static whitelist
            static_entry = await self.static_whitelist.is_whitelisted(
                event.tenant_id, 'ip', event.source_ip
            )
            if static_entry:
                return True, f"IP {event.source_ip} is statically whitelisted: {static_entry.reason}"
            
            # Check dynamic whitelist
            dynamic_entry = await self.dynamic_whitelist.is_dynamically_whitelisted(
                event.tenant_id, event.source_ip
            )
            if dynamic_entry:
                return True, f"IP {event.source_ip} is dynamically whitelisted (success count: {dynamic_entry['success_count']})"
            
            # Check business hours context
            if not await self.business_hours.is_business_hours(event.tenant_id, event.timestamp):
                # Outside business hours - apply stricter criteria
                if alert.alert_type == 'brute_force_attack' and alert.confidence < 0.8:
                    return True, "Low confidence brute force alert outside business hours"
            
            # Check behavioral analysis
            username = event.raw_data.get('username')
            if username:
                profile = await self.behavioral_analysis.get_user_profile(event.tenant_id, username)
                if profile:
                    suppress, reason = await self._check_behavioral_suppression(event, alert, profile)
                    if suppress:
                        return True, reason
            
            # Check for legitimate service patterns
            if await self._is_legitimate_service_activity(event, alert):
                return True, "Detected legitimate service activity pattern"
            
            # Check for post-success suppression
            if await self._check_post_success_suppression(event, alert):
                return True, "Alert suppressed due to recent successful authentication"
            
            return False, "No false positive indicators found"
            
        except Exception as e:
            logger.error(f"Error in false positive analysis: {e}")
            return False, "Error in FP analysis"
    
    async def _check_behavioral_suppression(self, event: ProcessedEvent, alert: ThreatAlert, 
                                          profile: UserBehaviorProfile) -> Tuple[bool, str]:
        """Check if alert should be suppressed based on behavioral analysis"""
        try:
            # Service accounts have different tolerance
            if profile.profile_type == 'service_account':
                if alert.alert_type == 'brute_force_attack':
                    failed_attempts = alert.evidence.get('failed_attempts', 0)
                    if failed_attempts <= profile.failure_tolerance:
                        return True, f"Service account within failure tolerance ({failed_attempts} <= {profile.failure_tolerance})"
            
            # Check if activity is within normal patterns
            current_hour = event.timestamp.hour
            current_day = event.timestamp.weekday() + 1
            
            if (current_hour in profile.typical_hours and 
                current_day in profile.typical_days and
                event.source_ip in profile.typical_ips):
                
                if alert.confidence < 0.7:  # Lower confidence for familiar patterns
                    return True, "Activity matches user's normal behavior pattern"
            
            return False, "No behavioral suppression criteria met"
            
        except Exception as e:
            logger.error(f"Error in behavioral suppression check: {e}")
            return False, "Error in behavioral analysis"
    
    async def _is_legitimate_service_activity(self, event: ProcessedEvent, alert: ThreatAlert) -> bool:
        """Check if activity appears to be from legitimate services"""
        try:
            user_agent = event.raw_data.get('user_agent', '').lower()
            
            # Known legitimate service patterns
            legitimate_patterns = [
                'monitoring', 'nagios', 'zabbix', 'prometheus',
                'backup', 'rsync', 'ansible', 'puppet', 'chef',
                'jenkins', 'gitlab', 'github', 'bitbucket',
                'docker', 'kubernetes', 'kubectl'
            ]
            
            if any(pattern in user_agent for pattern in legitimate_patterns):
                return True
            
            # Check for consistent automated behavior
            if alert.alert_type == 'port_scan_attack':
                ports = alert.evidence.get('ports_accessed', [])
                # Common monitoring ports
                monitoring_ports = {'22', '80', '443', '8080', '9090', '3000'}
                if set(ports).issubset(monitoring_ports):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking legitimate service activity: {e}")
            return False
    
    async def _check_post_success_suppression(self, event: ProcessedEvent, alert: ThreatAlert) -> bool:
        """Check if there was a recent successful authentication that should suppress the alert"""
        try:
            if alert.alert_type != 'brute_force_attack':
                return False
            
            # Check for recent successful authentication from same IP
            success_key = f"recent_success:{event.tenant_id}:{event.source_ip}"
            recent_success = await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.get, success_key
            )
            
            if recent_success:
                success_data = json.loads(recent_success)
                success_time = datetime.fromisoformat(success_data['timestamp'])
                
                # If success was within 5 minutes of the alert, suppress
                if (event.timestamp - success_time).total_seconds() < 300:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking post-success suppression: {e}")
            return False
    
    async def record_successful_authentication(self, tenant_id: str, source_ip: str, username: str):
        """Record successful authentication for dynamic whitelisting and suppression"""
        try:
            # Record for dynamic whitelisting
            await self.dynamic_whitelist.record_successful_auth(tenant_id, source_ip, username)
            
            # Record for post-success suppression
            success_key = f"recent_success:{tenant_id}:{source_ip}"
            success_data = {
                'username': username,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.setex, success_key, 300, json.dumps(success_data)  # 5 minutes
            )
            
        except Exception as e:
            logger.error(f"Error recording successful authentication: {e}")
    
    async def initialize_default_whitelists(self, tenant_id: str) -> bool:
        """Initialize default whitelist entries for a tenant"""
        try:
            # Common internal network ranges
            internal_networks = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '127.0.0.0/8'
            ]
            
            for network in internal_networks:
                entry = WhitelistEntry(
                    id=f"default_network_{network.replace('/', '_')}",
                    tenant_id=tenant_id,
                    entry_type='network',
                    value=network,
                    reason='Default internal network range',
                    created_at=datetime.utcnow(),
                    auto_generated=True
                )
                await self.static_whitelist.add_whitelist_entry(entry)
            
            # Common legitimate user agents
            legitimate_user_agents = [
                'Nagios',
                'Zabbix',
                'Prometheus',
                'Ansible',
                'Puppet'
            ]
            
            for ua in legitimate_user_agents:
                entry = WhitelistEntry(
                    id=f"default_ua_{ua.lower()}",
                    tenant_id=tenant_id,
                    entry_type='user_agent',
                    value=ua,
                    reason='Default legitimate monitoring tool',
                    created_at=datetime.utcnow(),
                    auto_generated=True
                )
                await self.static_whitelist.add_whitelist_entry(entry)
            
            logger.info(f"Initialized default whitelists for tenant {tenant_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing default whitelists: {e}")
            return False

# Global false positive reduction engine
fp_reduction_engine = FalsePositiveReductionEngine()

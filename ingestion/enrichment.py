"""
BITS-SIEM Message Enrichment Service
Tenant resolution, geo-location, and metadata enrichment
"""

import logging
import ipaddress
import json
from typing import Dict, Optional, Any, List
from datetime import datetime
import redis
from dataclasses import dataclass

from parsers import SyslogMessage
from config import config

logger = logging.getLogger(__name__)

@dataclass
class GeoLocation:
    """Geo-location information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None

class TenantResolver:
    """Resolve tenant ID from source IP address"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.ip_ranges = config.tenant.ip_ranges
        self.cache_ttl = config.tenant.cache_ttl
        self.default_tenant = config.tenant.default_tenant
        
        # Pre-compile IP networks for faster lookup
        self._compiled_ranges = {}
        self._compile_ip_ranges()
    
    def _compile_ip_ranges(self):
        """Pre-compile IP ranges for faster lookups"""
        for tenant_id, ranges in self.ip_ranges.items():
            compiled_ranges = []
            for ip_range in ranges:
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    compiled_ranges.append(network)
                except ValueError as e:
                    logger.error(f"Invalid IP range {ip_range} for tenant {tenant_id}: {e}")
            self._compiled_ranges[tenant_id] = compiled_ranges
    
    def resolve_tenant(self, source_ip: str) -> str:
        """Resolve tenant ID from source IP address"""
        if not source_ip:
            return self.default_tenant
        
        # Check cache first
        cache_key = f"tenant_resolve:{source_ip}"
        try:
            cached_result = self.redis.get(cache_key)
            if cached_result:
                return cached_result.decode('utf-8')
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        # Resolve tenant from IP ranges
        try:
            ip_addr = ipaddress.ip_address(source_ip)
            
            for tenant_id, networks in self._compiled_ranges.items():
                for network in networks:
                    if ip_addr in network:
                        # Cache the result
                        try:
                            self.redis.setex(cache_key, self.cache_ttl, tenant_id)
                        except Exception as e:
                            logger.warning(f"Redis cache write error: {e}")
                        return tenant_id
            
            # No match found, use default
            logger.info(f"No tenant match for IP {source_ip}, using default: {self.default_tenant}")
            return self.default_tenant
            
        except ValueError as e:
            logger.error(f"Invalid IP address {source_ip}: {e}")
            return self.default_tenant
    
    def get_tenant_stats(self) -> Dict[str, Any]:
        """Get tenant resolution statistics"""
        stats = {
            'total_tenants': len(self.ip_ranges),
            'default_tenant': self.default_tenant,
            'ip_ranges': {tenant: len(ranges) for tenant, ranges in self.ip_ranges.items()}
        }
        return stats

class GeoLocationService:
    """Geo-location service using MaxMind GeoIP2"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.enabled = config.enrichment.geoip_enabled
        self.db_path = config.enrichment.geoip_db_path
        self.geoip_reader = None
        
        if self.enabled:
            self._initialize_geoip()
    
    def _initialize_geoip(self):
        """Initialize GeoIP2 reader"""
        try:
            import geoip2.database
            self.geoip_reader = geoip2.database.Reader(self.db_path)
            logger.info(f"GeoIP2 database loaded: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to load GeoIP2 database: {e}")
            self.enabled = False
    
    def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geo-location for IP address"""
        if not self.enabled or not ip_address:
            return None
        
        # Check cache first
        cache_key = f"geoip:{ip_address}"
        try:
            cached_result = self.redis.get(cache_key)
            if cached_result:
                data = json.loads(cached_result.decode('utf-8'))
                return GeoLocation(**data)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")
        
        # Query GeoIP database
        try:
            response = self.geoip_reader.city(ip_address)
            
            location = GeoLocation(
                country=response.country.name,
                country_code=response.country.iso_code,
                city=response.city.name,
                region=response.subdivisions.most_specific.name,
                latitude=float(response.location.latitude) if response.location.latitude else None,
                longitude=float(response.location.longitude) if response.location.longitude else None,
                timezone=response.location.time_zone,
                isp=response.traits.isp if hasattr(response.traits, 'isp') else None
            )
            
            # Cache the result
            try:
                cache_data = {
                    'country': location.country,
                    'country_code': location.country_code,
                    'city': location.city,
                    'region': location.region,
                    'latitude': location.latitude,
                    'longitude': location.longitude,
                    'timezone': location.timezone,
                    'isp': location.isp
                }
                self.redis.setex(cache_key, 3600, json.dumps(cache_data))  # Cache for 1 hour
            except Exception as e:
                logger.warning(f"Redis cache write error: {e}")
            
            return location
            
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip_address}: {e}")
            return None
    
    def close(self):
        """Close GeoIP2 reader"""
        if self.geoip_reader:
            self.geoip_reader.close()

class MetadataEnricher:
    """Add metadata and context to syslog messages"""
    
    def __init__(self):
        self.enabled = config.enrichment.metadata_enabled
    
    def enrich_metadata(self, message: SyslogMessage) -> Dict[str, Any]:
        """Add metadata to syslog message"""
        if not self.enabled:
            return {}
        
        metadata = {
            'ingestion_timestamp': datetime.utcnow().isoformat(),
            'parser_version': '1.0.0',
            'source_type': 'syslog'
        }
        
        # Add facility and severity names
        if message.facility is not None:
            from parsers import SyslogFacility
            metadata['facility_name'] = SyslogFacility.get_facility_name(message.facility)
        
        if message.severity is not None:
            from parsers import SyslogSeverity
            metadata['severity_name'] = SyslogSeverity.get_severity_name(message.severity)
        
        # Add message classification
        if message.message:
            metadata['message_classification'] = self._classify_message(message.message)
        
        # Add hostname validation
        if message.hostname:
            metadata['hostname_is_ip'] = self._is_ip_address(message.hostname)
        
        return metadata
    
    def _classify_message(self, message: str) -> str:
        """Basic message classification"""
        message_lower = message.lower()
        
        # Security-related keywords
        if any(keyword in message_lower for keyword in ['failed', 'error', 'denied', 'blocked', 'rejected']):
            return 'security'
        elif any(keyword in message_lower for keyword in ['login', 'logout', 'session', 'authentication']):
            return 'authentication'
        elif any(keyword in message_lower for keyword in ['connection', 'disconnect', 'network']):
            return 'network'
        elif any(keyword in message_lower for keyword in ['started', 'stopped', 'service', 'daemon']):
            return 'system'
        else:
            return 'general'
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

class MessageEnricher:
    """Main message enrichment service"""
    
    def __init__(self):
        # Initialize Redis connection
        self.redis_client = self._init_redis()
        
        # Initialize enrichment services
        self.tenant_resolver = TenantResolver(self.redis_client)
        self.geo_service = GeoLocationService(self.redis_client)
        self.metadata_enricher = MetadataEnricher()
        
        # Statistics
        self.stats = {
            'messages_enriched': 0,
            'tenant_resolutions': 0,
            'geo_lookups': 0,
            'enrichment_errors': 0
        }
    
    def _init_redis(self) -> redis.Redis:
        """Initialize Redis connection"""
        try:
            return redis.Redis(
                host=config.redis.host,
                port=config.redis.port,
                db=config.redis.db,
                password=config.redis.password,
                max_connections=config.redis.max_connections,
                decode_responses=False
            )
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def enrich_message(self, message: SyslogMessage) -> SyslogMessage:
        """Enrich a syslog message with tenant, geo-location, and metadata"""
        try:
            self.stats['messages_enriched'] += 1
            
            # Resolve tenant ID
            if config.enrichment.tenant_resolution_enabled and message.source_ip:
                message.tenant_id = self.tenant_resolver.resolve_tenant(message.source_ip)
                self.stats['tenant_resolutions'] += 1
            
            # Add geo-location
            if config.enrichment.geoip_enabled and message.source_ip:
                geo_location = self.geo_service.get_location(message.source_ip)
                if geo_location:
                    message.geo_location = {
                        'country': geo_location.country,
                        'country_code': geo_location.country_code,
                        'city': geo_location.city,
                        'region': geo_location.region,
                        'latitude': geo_location.latitude,
                        'longitude': geo_location.longitude,
                        'timezone': geo_location.timezone,
                        'isp': geo_location.isp
                    }
                    self.stats['geo_lookups'] += 1
            
            # Add metadata
            if config.enrichment.metadata_enabled:
                message.metadata = self.metadata_enricher.enrich_metadata(message)
            
            return message
            
        except Exception as e:
            self.stats['enrichment_errors'] += 1
            logger.error(f"Message enrichment failed: {e}")
            return message
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enrichment statistics"""
        return {
            'enrichment': self.stats.copy(),
            'tenant_resolver': self.tenant_resolver.get_tenant_stats(),
            'redis_info': {
                'connected': self.redis_client.ping() if self.redis_client else False
            }
        }
    
    def close(self):
        """Close connections"""
        if self.geo_service:
            self.geo_service.close()
        if self.redis_client:
            self.redis_client.close()

# Global enricher instance
enricher = MessageEnricher()

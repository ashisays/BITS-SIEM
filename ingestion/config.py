"""
BITS-SIEM Ingestion Service Configuration
Multi-protocol syslog ingestion with tenant isolation
"""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class SyslogConfig:
    """Syslog listener configuration"""
    protocol: str  # udp, tcp, tls
    host: str
    port: int
    buffer_size: int
    timeout: int
    enabled: bool = True

@dataclass
class DatabaseConfig:
    """Database connection configuration"""
    url: str
    pool_size: int
    max_overflow: int
    pool_timeout: int
    pool_recycle: int

@dataclass
class RedisConfig:
    """Redis cache configuration"""
    host: str
    port: int
    db: int
    password: Optional[str]
    max_connections: int

@dataclass
class TenantConfig:
    """Tenant resolution configuration"""
    ip_ranges: Dict[str, List[str]]  # tenant_id -> list of IP ranges
    default_tenant: str
    cache_ttl: int

@dataclass
class EnrichmentConfig:
    """Message enrichment configuration"""
    geoip_enabled: bool
    geoip_db_path: str
    metadata_enabled: bool
    tenant_resolution_enabled: bool

class IngestionConfig:
    """Main ingestion service configuration"""
    
    def __init__(self):
        # Service configuration
        self.service_name = os.getenv("SERVICE_NAME", "ingestion-service")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        
        # Syslog listeners
        self.syslog_listeners = {
            "udp": SyslogConfig(
                protocol="udp",
                host=os.getenv("SYSLOG_UDP_HOST", "0.0.0.0"),
                port=int(os.getenv("SYSLOG_UDP_PORT", "514")),
                buffer_size=int(os.getenv("SYSLOG_UDP_BUFFER", "65536")),
                timeout=int(os.getenv("SYSLOG_UDP_TIMEOUT", "5")),
                enabled=os.getenv("SYSLOG_UDP_ENABLED", "true").lower() == "true"
            ),
            "tcp": SyslogConfig(
                protocol="tcp",
                host=os.getenv("SYSLOG_TCP_HOST", "0.0.0.0"),
                port=int(os.getenv("SYSLOG_TCP_PORT", "514")),
                buffer_size=int(os.getenv("SYSLOG_TCP_BUFFER", "65536")),
                timeout=int(os.getenv("SYSLOG_TCP_TIMEOUT", "30")),
                enabled=os.getenv("SYSLOG_TCP_ENABLED", "true").lower() == "true"
            ),
            "tls": SyslogConfig(
                protocol="tls",
                host=os.getenv("SYSLOG_TLS_HOST", "0.0.0.0"),
                port=int(os.getenv("SYSLOG_TLS_PORT", "6514")),
                buffer_size=int(os.getenv("SYSLOG_TLS_BUFFER", "65536")),
                timeout=int(os.getenv("SYSLOG_TLS_TIMEOUT", "30")),
                enabled=os.getenv("SYSLOG_TLS_ENABLED", "false").lower() == "true"
            )
        }
        
        # Database configuration
        self.database = DatabaseConfig(
            url=os.getenv("DATABASE_URL", "postgresql+psycopg2://siem:siempassword@db:5432/siemdb"),
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "3600"))
        )
        
        # Redis configuration
        self.redis = RedisConfig(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=int(os.getenv("REDIS_DB", "0")),
            password=os.getenv("REDIS_PASSWORD"),
            max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
        )
        
        # Tenant configuration
        self.tenant = TenantConfig(
            ip_ranges=self._load_tenant_ip_ranges(),
            default_tenant=os.getenv("DEFAULT_TENANT", "demo-org"),
            cache_ttl=int(os.getenv("TENANT_CACHE_TTL", "300"))
        )
        
        # Enrichment configuration
        self.enrichment = EnrichmentConfig(
            geoip_enabled=os.getenv("GEOIP_ENABLED", "false").lower() == "true",
            geoip_db_path=os.getenv("GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb"),
            metadata_enabled=os.getenv("METADATA_ENABLED", "true").lower() == "true",
            tenant_resolution_enabled=os.getenv("TENANT_RESOLUTION_ENABLED", "true").lower() == "true"
        )
        
        # Processing configuration
        self.batch_size = int(os.getenv("BATCH_SIZE", "100"))
        self.batch_timeout = int(os.getenv("BATCH_TIMEOUT", "5"))
        self.max_workers = int(os.getenv("MAX_WORKERS", "4"))
        
        # Monitoring configuration
        self.metrics_enabled = os.getenv("METRICS_ENABLED", "true").lower() == "true"
        self.metrics_port = int(os.getenv("METRICS_PORT", "8000"))
        
        # TLS configuration
        self.tls_cert_path = os.getenv("TLS_CERT_PATH", "/certs/server.crt")
        self.tls_key_path = os.getenv("TLS_KEY_PATH", "/certs/server.key")
        self.tls_ca_path = os.getenv("TLS_CA_PATH", "/certs/ca.crt")
    
    def _load_tenant_ip_ranges(self) -> Dict[str, List[str]]:
        """Load tenant IP ranges from environment or configuration"""
        # Default tenant IP ranges based on existing database schema
        default_ranges = {
            "acme-corp": ["10.0.1.0/24", "192.168.1.0/24"],
            "beta-industries": ["10.0.2.0/24", "192.168.2.0/24"],
            "cisco-systems": ["10.0.3.0/24", "192.168.3.0/24"],
            "demo-org": ["10.0.0.0/24", "192.168.0.0/24"],
            "bits-internal": ["172.20.0.0/24", "10.10.0.0/24"]
        }
        
        # Load from environment if available
        tenant_ranges_env = os.getenv("TENANT_IP_RANGES")
        if tenant_ranges_env:
            try:
                import json
                return json.loads(tenant_ranges_env)
            except json.JSONDecodeError:
                pass
        
        return default_ranges
    
    def get_enabled_listeners(self) -> List[SyslogConfig]:
        """Get list of enabled syslog listeners"""
        return [config for config in self.syslog_listeners.values() if config.enabled]
    
    def is_tls_enabled(self) -> bool:
        """Check if TLS is enabled and properly configured"""
        return (self.syslog_listeners["tls"].enabled and 
                os.path.exists(self.tls_cert_path) and 
                os.path.exists(self.tls_key_path))

# Global configuration instance
config = IngestionConfig()

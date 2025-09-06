"""
BITS-SIEM Processing Service Configuration
Stream processing and threat detection configuration
"""

import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class StreamConfig:
    """Stream processing configuration"""
    backend: str  # redis, kafka
    batch_size: int
    batch_timeout: float
    max_workers: int
    buffer_size: int

@dataclass
class ThreatDetectionConfig:
    """Threat detection configuration"""
    brute_force_enabled: bool
    brute_force_threshold: int
    brute_force_window: int
    port_scan_enabled: bool
    port_scan_threshold: int
    port_scan_window: int
    anomaly_detection_enabled: bool
    correlation_enabled: bool
    false_positive_reduction_enabled: bool
    dynamic_whitelist_enabled: bool
    behavioral_analysis_enabled: bool
    business_hours_enabled: bool

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
    """Redis configuration"""
    host: str
    port: int
    db: int
    password: Optional[str]
    max_connections: int

@dataclass
class KafkaConfig:
    """Kafka configuration"""
    bootstrap_servers: List[str]
    consumer_group: str
    topics: Dict[str, str]
    auto_offset_reset: str
    enable_auto_commit: bool

@dataclass
class AlertConfig:
    """Alert configuration"""
    enabled: bool
    webhook_url: Optional[str]
    websocket_enabled: bool
    websocket_port: int
    email_notifications: bool
    alert_cooldown: int
    correlation_window: int
    max_correlation_distance: float
    notification_channels: list
    rate_limit_window: int
    max_notifications_per_window: int
    default_cooldown: int

@dataclass
class MLConfig:
    """Machine learning configuration"""
    model_path: str
    retrain_interval: int
    anomaly_threshold: float
    feature_window: int
    min_samples: int

class ProcessingConfig:
    """Main processing service configuration"""
    
    def __init__(self):
        # Service configuration
        self.service_name = os.getenv("SERVICE_NAME", "processing-service")
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.environment = os.getenv("ENVIRONMENT", "development")
        
        # API configuration
        self.api_host = os.getenv("API_HOST", "0.0.0.0")
        self.api_port = int(os.getenv("API_PORT", "8001"))
        
        # Stream processing configuration
        self.stream = StreamConfig(
            backend=os.getenv("STREAM_BACKEND", "redis"),
            batch_size=int(os.getenv("STREAM_BATCH_SIZE", "50")),
            batch_timeout=float(os.getenv("STREAM_BATCH_TIMEOUT", "5.0")),
            max_workers=int(os.getenv("STREAM_MAX_WORKERS", "4")),
            buffer_size=int(os.getenv("STREAM_BUFFER_SIZE", "1000"))
        )
        
        # Threat detection configuration
        self.threat_detection = ThreatDetectionConfig(
            brute_force_enabled=os.getenv("BRUTE_FORCE_ENABLED", "true").lower() == "true",
            brute_force_threshold=int(os.getenv("BRUTE_FORCE_THRESHOLD", "5")),
            brute_force_window=int(os.getenv("BRUTE_FORCE_WINDOW", "300")),  # 5 minutes
            port_scan_enabled=os.getenv("PORT_SCAN_ENABLED", "true").lower() == "true",
            port_scan_threshold=int(os.getenv("PORT_SCAN_THRESHOLD", "10")),
            port_scan_window=int(os.getenv("PORT_SCAN_WINDOW", "600")),  # 10 minutes
            anomaly_detection_enabled=os.getenv("ANOMALY_DETECTION_ENABLED", "true").lower() == "true",
            correlation_enabled=os.getenv("CORRELATION_ENABLED", "true").lower() == "true",
            false_positive_reduction_enabled=os.getenv("FALSE_POSITIVE_REDUCTION_ENABLED", "true").lower() == "true",
            dynamic_whitelist_enabled=os.getenv("DYNAMIC_WHITELIST_ENABLED", "true").lower() == "true",
            behavioral_analysis_enabled=os.getenv("BEHAVIORAL_ANALYSIS_ENABLED", "true").lower() == "true",
            business_hours_enabled=os.getenv("BUSINESS_HOURS_ENABLED", "true").lower() == "true"
        )
        
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
            db=int(os.getenv("REDIS_DB", "0")),  # Use same DB as ingestion for threat detection
            password=os.getenv("REDIS_PASSWORD"),
            max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "20"))
        )
        
        # Kafka configuration
        self.kafka = KafkaConfig(
            bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092").split(","),
            consumer_group=os.getenv("KAFKA_CONSUMER_GROUP", "siem-processing"),
            topics={
                "raw_messages": os.getenv("KAFKA_RAW_MESSAGES_TOPIC", "siem-raw-messages"),
                "processed_events": os.getenv("KAFKA_PROCESSED_EVENTS_TOPIC", "siem-processed-events"),
                "alerts": os.getenv("KAFKA_ALERTS_TOPIC", "siem-alerts")
            },
            auto_offset_reset=os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest"),
            enable_auto_commit=os.getenv("KAFKA_ENABLE_AUTO_COMMIT", "true").lower() == "true"
        )
        
        # Alert configuration
        self.alerts = AlertConfig(
            enabled=os.getenv("ALERTS_ENABLED", "true").lower() == "true",
            webhook_url=os.getenv("ALERT_WEBHOOK_URL"),
            websocket_enabled=os.getenv("WEBSOCKET_ENABLED", "true").lower() == "true",
            websocket_port=int(os.getenv("WEBSOCKET_PORT", "8002")),
            email_notifications=os.getenv("EMAIL_NOTIFICATIONS", "true").lower() == "true",
            alert_cooldown=int(os.getenv("ALERT_COOLDOWN", "300")),  # 5 minutes
            correlation_window=int(os.getenv("ALERT_CORRELATION_WINDOW", "3600")),  # 1 hour
            max_correlation_distance=float(os.getenv("MAX_CORRELATION_DISTANCE", "0.8")),
            notification_channels=os.getenv("NOTIFICATION_CHANNELS", "email,webhook").split(","),
            rate_limit_window=int(os.getenv("RATE_LIMIT_WINDOW", "300")),  # 5 minutes
            max_notifications_per_window=int(os.getenv("MAX_NOTIFICATIONS_PER_WINDOW", "10")),
            default_cooldown=int(os.getenv("DEFAULT_COOLDOWN", "300"))  # 5 minutes
        )
        
        # Machine learning configuration
        self.ml = MLConfig(
            model_path=os.getenv("ML_MODEL_PATH", "/app/models"),
            retrain_interval=int(os.getenv("ML_RETRAIN_INTERVAL", "86400")),  # 24 hours
            anomaly_threshold=float(os.getenv("ML_ANOMALY_THRESHOLD", "0.95")),
            feature_window=int(os.getenv("ML_FEATURE_WINDOW", "3600")),  # 1 hour
            min_samples=int(os.getenv("ML_MIN_SAMPLES", "100"))
        )
        
        # Monitoring configuration
        self.metrics_enabled = os.getenv("METRICS_ENABLED", "true").lower() == "true"
        self.metrics_port = int(os.getenv("METRICS_PORT", "8003"))
        
        # Processing thresholds
        self.risk_score_threshold = float(os.getenv("RISK_SCORE_THRESHOLD", "0.75"))
        self.correlation_window = int(os.getenv("CORRELATION_WINDOW", "1800"))  # 30 minutes
        
        # Tenant configuration
        self.tenant_isolation = os.getenv("TENANT_ISOLATION", "true").lower() == "true"
        
        # Performance tuning
        self.max_memory_usage = os.getenv("MAX_MEMORY_USAGE", "1GB")
        self.cleanup_interval = int(os.getenv("CLEANUP_INTERVAL", "3600"))  # 1 hour
    
    def get_stream_topics(self) -> List[str]:
        """Get list of stream topics to consume"""
        if self.stream.backend == "kafka":
            return list(self.kafka.topics.values())
        else:
            return ["siem:raw_messages"]
    
    def get_detection_engines(self) -> List[str]:
        """Get list of enabled detection engines"""
        engines = []
        if self.threat_detection.brute_force_enabled:
            engines.append("brute_force")
        if self.threat_detection.port_scan_enabled:
            engines.append("port_scan")
        if self.threat_detection.anomaly_detection_enabled:
            engines.append("anomaly_detection")
        return engines
    
    def is_stream_backend_kafka(self) -> bool:
        """Check if using Kafka as stream backend"""
        return self.stream.backend.lower() == "kafka"
    
    def is_stream_backend_redis(self) -> bool:
        """Check if using Redis as stream backend"""
        return self.stream.backend.lower() == "redis"
    
    def get_alert_channels(self) -> List[str]:
        """Get list of enabled alert channels"""
        channels = []
        if self.alerts.webhook_url:
            channels.append("webhook")
        if self.alerts.websocket_enabled:
            channels.append("websocket")
        if self.alerts.email_notifications:
            channels.append("email")
        return channels
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate stream backend
        if self.stream.backend not in ["redis", "kafka"]:
            errors.append(f"Invalid stream backend: {self.stream.backend}")
        
        # Validate thresholds
        if self.threat_detection.brute_force_threshold <= 0:
            errors.append("Brute force threshold must be positive")
        
        if self.threat_detection.port_scan_threshold <= 0:
            errors.append("Port scan threshold must be positive")
        
        if self.risk_score_threshold < 0 or self.risk_score_threshold > 1:
            errors.append("Risk score threshold must be between 0 and 1")
        
        if self.ml.anomaly_threshold < 0 or self.ml.anomaly_threshold > 1:
            errors.append("Anomaly threshold must be between 0 and 1")
        
        # Validate ports
        if self.api_port <= 0 or self.api_port > 65535:
            errors.append("API port must be between 1 and 65535")
        
        if self.alerts.websocket_port <= 0 or self.alerts.websocket_port > 65535:
            errors.append("WebSocket port must be between 1 and 65535")
        
        if self.metrics_port <= 0 or self.metrics_port > 65535:
            errors.append("Metrics port must be between 1 and 65535")
        
        return errors
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for logging"""
        return {
            "service": {
                "name": self.service_name,
                "environment": self.environment,
                "debug": self.debug
            },
            "stream": {
                "backend": self.stream.backend,
                "batch_size": self.stream.batch_size,
                "workers": self.stream.max_workers
            },
            "threat_detection": {
                "engines": self.get_detection_engines(),
                "brute_force_threshold": self.threat_detection.brute_force_threshold,
                "port_scan_threshold": self.threat_detection.port_scan_threshold
            },
            "alerts": {
                "enabled": self.alerts.enabled,
                "channels": self.get_alert_channels()
            },
            "ml": {
                "enabled": self.ml.anomaly_threshold > 0,
                "threshold": self.ml.anomaly_threshold
            }
        }

# Global configuration instance
config = ProcessingConfig()

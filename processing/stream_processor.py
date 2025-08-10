"""
BITS-SIEM Stream Processing Pipeline
Real-time processing of syslog messages from ingestion service
"""

import asyncio
import logging
import json
import redis
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import structlog
from abc import ABC, abstractmethod

from config import config

logger = structlog.get_logger(__name__)

@dataclass
class ProcessedEvent:
    """Processed event structure"""
    id: str
    tenant_id: str
    source_ip: str
    timestamp: datetime
    event_type: str
    severity: str
    message: str
    raw_data: Dict[str, Any]
    enriched_data: Dict[str, Any]
    risk_score: float = 0.0
    tags: List[str] = None
    correlation_id: Optional[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        if isinstance(data.get('timestamp'), datetime):
            data['timestamp'] = self.timestamp.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProcessedEvent':
        """Create from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)

class StreamBackend(ABC):
    """Abstract base class for stream backends"""
    
    @abstractmethod
    async def initialize(self):
        """Initialize the backend"""
        pass
    
    @abstractmethod
    async def consume_messages(self, topics: List[str], handler: Callable):
        """Consume messages from topics"""
        pass
    
    @abstractmethod
    async def produce_message(self, topic: str, message: Dict[str, Any]):
        """Produce message to topic"""
        pass
    
    @abstractmethod
    async def close(self):
        """Close the backend"""
        pass

class RedisStreamBackend(StreamBackend):
    """Redis-based stream processing backend"""
    
    def __init__(self):
        self.redis_client = None
        self.consumer_group = "siem-processing"
        self.consumer_name = f"processor-{datetime.now().timestamp()}"
        self.stats = {
            'messages_consumed': 0,
            'messages_produced': 0,
            'processing_errors': 0,
            'connection_errors': 0
        }
    
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=config.redis.host,
                port=config.redis.port,
                db=config.redis.db,
                password=config.redis.password,
                max_connections=config.redis.max_connections,
                decode_responses=True
            )
            
            # Test connection
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.ping
            )
            
            logger.info("Redis stream backend initialized")
            
        except Exception as e:
            self.stats['connection_errors'] += 1
            logger.error(f"Failed to initialize Redis backend: {e}")
            raise
    
    async def consume_messages(self, topics: List[str], handler: Callable):
        """Consume messages from Redis streams"""
        try:
            # Create consumer groups if they don't exist
            for topic in topics:
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, 
                        self.redis_client.xgroup_create,
                        topic, self.consumer_group, '0', True
                    )
                except redis.exceptions.ResponseError:
                    # Consumer group already exists
                    pass
            
            while True:
                try:
                    # Read messages from all topics
                    streams = {topic: '>' for topic in topics}
                    
                    from functools import partial
                    messages = await asyncio.get_event_loop().run_in_executor(
                        None,
                        partial(
                            self.redis_client.xreadgroup,
                            self.consumer_group,
                            self.consumer_name,
                            streams,
                            count=config.stream.batch_size,
                            block=int(config.stream.batch_timeout * 1000)
                        )
                    )
                    
                    if messages:
                        await self._process_batch(messages, handler)
                    
                except redis.exceptions.RedisError as e:
                    self.stats['connection_errors'] += 1
                    logger.error(f"Redis error: {e}")
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    self.stats['processing_errors'] += 1
                    logger.error(f"Error processing messages: {e}")
                    await asyncio.sleep(1)
                    
        except asyncio.CancelledError:
            logger.info("Message consumption cancelled")
        except Exception as e:
            logger.error(f"Fatal error in message consumption: {e}")
            raise
    
    async def _process_batch(self, messages: List, handler: Callable):
        """Process a batch of messages"""
        for stream_name, stream_messages in messages:
            for message_id, fields in stream_messages:
                try:
                    # Deserialize message
                    message_data = json.loads(fields.get('data', '{}'))
                    
                    # Process message
                    await handler(message_data)
                    
                    # Acknowledge message
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.redis_client.xack,
                        stream_name,
                        self.consumer_group,
                        message_id
                    )
                    
                    self.stats['messages_consumed'] += 1
                    
                except Exception as e:
                    self.stats['processing_errors'] += 1
                    logger.error(f"Error processing message {message_id}: {e}")
    
    async def produce_message(self, topic: str, message: Dict[str, Any]):
        """Produce message to Redis stream"""
        try:
            message_data = json.dumps(message)
            
            from functools import partial
            await asyncio.get_event_loop().run_in_executor(
                None,
                partial(
                    self.redis_client.xadd,
                    topic,
                    {'data': message_data},
                    maxlen=10000,  # Keep only last 10k messages
                    approximate=True
                )
            )
            
            self.stats['messages_produced'] += 1
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error producing message to {topic}: {e}")
            raise
    
    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            self.redis_client.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backend statistics"""
        return self.stats.copy()

class KafkaStreamBackend(StreamBackend):
    """Kafka-based stream processing backend"""
    
    def __init__(self):
        self.consumer = None
        self.producer = None
        self.stats = {
            'messages_consumed': 0,
            'messages_produced': 0,
            'processing_errors': 0,
            'connection_errors': 0
        }
    
    async def initialize(self):
        """Initialize Kafka connection"""
        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
            
            # Initialize consumer
            self.consumer = AIOKafkaConsumer(
                *config.kafka.topics.values(),
                bootstrap_servers=config.kafka.bootstrap_servers,
                group_id=config.kafka.consumer_group,
                auto_offset_reset=config.kafka.auto_offset_reset,
                enable_auto_commit=config.kafka.enable_auto_commit,
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )
            
            # Initialize producer
            self.producer = AIOKafkaProducer(
                bootstrap_servers=config.kafka.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            
            # Start connections
            await self.consumer.start()
            await self.producer.start()
            
            logger.info("Kafka stream backend initialized")
            
        except Exception as e:
            self.stats['connection_errors'] += 1
            logger.error(f"Failed to initialize Kafka backend: {e}")
            raise
    
    async def consume_messages(self, topics: List[str], handler: Callable):
        """Consume messages from Kafka topics"""
        try:
            async for message in self.consumer:
                try:
                    # Process message
                    await handler(message.value)
                    
                    self.stats['messages_consumed'] += 1
                    
                except Exception as e:
                    self.stats['processing_errors'] += 1
                    logger.error(f"Error processing message: {e}")
                    
        except asyncio.CancelledError:
            logger.info("Message consumption cancelled")
        except Exception as e:
            logger.error(f"Fatal error in message consumption: {e}")
            raise
    
    async def produce_message(self, topic: str, message: Dict[str, Any]):
        """Produce message to Kafka topic"""
        try:
            await self.producer.send(topic, message)
            self.stats['messages_produced'] += 1
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error producing message to {topic}: {e}")
            raise
    
    async def close(self):
        """Close Kafka connections"""
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backend statistics"""
        return self.stats.copy()

class MessageProcessor:
    """Process individual messages and apply transformations"""
    
    def __init__(self):
        self.stats = {
            'messages_processed': 0,
            'events_generated': 0,
            'processing_errors': 0,
            'classification_errors': 0
        }
    
    async def process_message(self, raw_message: Dict[str, Any]) -> Optional[ProcessedEvent]:
        """Process a raw syslog message into a structured event"""
        try:
            # Extract basic information
            event_id = f"{raw_message.get('tenant_id', 'unknown')}_{datetime.now().timestamp()}"
            tenant_id = raw_message.get('tenant_id', 'unknown')
            source_ip = raw_message.get('source_ip', 'unknown')
            timestamp = self._parse_timestamp(raw_message.get('timestamp'))
            
            # Classify event type
            event_type = await self._classify_event_type(raw_message)
            
            # Calculate initial risk score
            risk_score = await self._calculate_risk_score(raw_message, event_type)
            
            # Extract severity
            severity = self._extract_severity(raw_message)
            
            # Create processed event
            event = ProcessedEvent(
                id=event_id,
                tenant_id=tenant_id,
                source_ip=source_ip,
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                message=raw_message.get('message', ''),
                raw_data=raw_message,
                enriched_data=raw_message.get('enriched_data', {}),
                risk_score=risk_score,
                tags=self._generate_tags(raw_message, event_type)
            )
            
            self.stats['messages_processed'] += 1
            self.stats['events_generated'] += 1
            
            return event
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error processing message: {e}")
            return None
    
    async def _classify_event_type(self, message: Dict[str, Any]) -> str:
        """Classify the event type based on message content"""
        try:
            msg_content = message.get('message', '').lower()
            program = message.get('program', '').lower()
            
            # Authentication events
            if any(keyword in msg_content for keyword in ['login', 'authentication', 'password', 'failed']):
                if any(keyword in msg_content for keyword in ['failed', 'invalid', 'incorrect']):
                    return 'authentication_failure'
                else:
                    return 'authentication_success'
            
            # Network events
            elif any(keyword in msg_content for keyword in ['connection', 'connect', 'disconnect']):
                return 'network_connection'
            
            # System events
            elif any(keyword in msg_content for keyword in ['started', 'stopped', 'service', 'daemon']):
                return 'system_event'
            
            # Security events
            elif any(keyword in msg_content for keyword in ['blocked', 'denied', 'rejected', 'firewall']):
                return 'security_event'
            
            # SSH events
            elif 'ssh' in program:
                return 'ssh_event'
            
            # Web server events
            elif program in ['apache', 'nginx', 'httpd']:
                return 'web_server_event'
            
            # Database events
            elif program in ['mysql', 'postgresql', 'mongodb']:
                return 'database_event'
            
            else:
                return 'general_event'
                
        except Exception as e:
            self.stats['classification_errors'] += 1
            logger.error(f"Error classifying event: {e}")
            return 'unknown_event'
    
    async def _calculate_risk_score(self, message: Dict[str, Any], event_type: str) -> float:
        """Calculate initial risk score for the event"""
        try:
            base_score = 0.0
            
            # Base score by event type
            type_scores = {
                'authentication_failure': 0.7,
                'security_event': 0.8,
                'network_connection': 0.3,
                'system_event': 0.2,
                'ssh_event': 0.5,
                'web_server_event': 0.3,
                'database_event': 0.4,
                'general_event': 0.1
            }
            
            base_score = type_scores.get(event_type, 0.1)
            
            # Adjust based on severity
            severity = message.get('severity', 6)
            if severity <= 2:  # Emergency, Alert, Critical
                base_score += 0.2
            elif severity <= 4:  # Error, Warning
                base_score += 0.1
            
            # Adjust based on source IP patterns
            source_ip = message.get('source_ip', '')
            if source_ip:
                # External IPs might be more risky
                if not source_ip.startswith(('10.', '192.168.', '172.')):
                    base_score += 0.1
            
            # Adjust based on message content
            msg_content = message.get('message', '').lower()
            risk_keywords = ['attack', 'intrusion', 'malware', 'virus', 'breach', 'exploit', 'suspicious']
            for keyword in risk_keywords:
                if keyword in msg_content:
                    base_score += 0.1
                    break
            
            # Ensure score is between 0 and 1
            return min(max(base_score, 0.0), 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.5  # Default medium risk
    
    def _extract_severity(self, message: Dict[str, Any]) -> str:
        """Extract severity level from message"""
        severity_map = {
            0: 'emergency',
            1: 'alert',
            2: 'critical',
            3: 'error',
            4: 'warning',
            5: 'notice',
            6: 'info',
            7: 'debug'
        }
        
        severity_code = message.get('severity', 6)
        return severity_map.get(severity_code, 'info')
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse timestamp string to datetime object"""
        if not timestamp_str:
            return datetime.utcnow()
        
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()
    
    def _generate_tags(self, message: Dict[str, Any], event_type: str) -> List[str]:
        """Generate tags for the event"""
        tags = [event_type]
        
        # Add program tag
        program = message.get('program')
        if program:
            tags.append(f"program:{program}")
        
        # Add facility tag
        facility = message.get('facility')
        if facility is not None:
            tags.append(f"facility:{facility}")
        
        # Add tenant tag
        tenant_id = message.get('tenant_id')
        if tenant_id:
            tags.append(f"tenant:{tenant_id}")
        
        return tags
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics"""
        return self.stats.copy()

class StreamProcessor:
    """Main stream processor orchestrator"""
    
    def __init__(self):
        self.backend = None
        self.message_processor = MessageProcessor()
        self.running = False
        self.stats = {
            'start_time': None,
            'uptime_seconds': 0,
            'total_processed': 0,
            'events_generated': 0,
            'processing_errors': 0
        }
    
    async def initialize(self):
        """Initialize the stream processor"""
        try:
            # Initialize backend
            if config.is_stream_backend_kafka():
                self.backend = KafkaStreamBackend()
            else:
                self.backend = RedisStreamBackend()
            
            await self.backend.initialize()
            
            logger.info(f"Stream processor initialized with {config.stream.backend} backend")
            
        except Exception as e:
            logger.error(f"Failed to initialize stream processor: {e}")
            raise
    
    async def start(self, event_handler: Callable):
        """Start stream processing"""
        try:
            self.running = True
            self.stats['start_time'] = datetime.utcnow()
            
            logger.info("Starting stream processor")
            
            # Start consuming messages
            topics = config.get_stream_topics()
            
            async def message_handler(raw_message: Dict[str, Any]):
                """Handle individual messages"""
                try:
                    # Process message
                    event = await self.message_processor.process_message(raw_message)
                    
                    if event:
                        # Pass to event handler (threat detection) - wrap single event in list
                        await event_handler([event])
                        
                        # Produce processed event
                        await self.backend.produce_message(
                            "siem:processed_events",
                            event.to_dict()
                        )
                        
                        self.stats['events_generated'] += 1
                    
                    self.stats['total_processed'] += 1
                    
                except Exception as e:
                    self.stats['processing_errors'] += 1
                    logger.error(f"Error in message handler: {e}")
            
            # Start consuming
            await self.backend.consume_messages(topics, message_handler)
            
        except Exception as e:
            logger.error(f"Error in stream processor: {e}")
            raise
    
    async def stop(self):
        """Stop stream processing"""
        self.running = False
        
        if self.backend:
            await self.backend.close()
        
        logger.info("Stream processor stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        if self.stats['start_time']:
            self.stats['uptime_seconds'] = (datetime.utcnow() - self.stats['start_time']).total_seconds()
        
        return {
            'processor': self.stats.copy(),
            'backend': self.backend.get_stats() if self.backend else {},
            'message_processor': self.message_processor.get_stats()
        }

# Global stream processor instance
stream_processor = StreamProcessor()

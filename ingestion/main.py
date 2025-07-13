#!/usr/bin/env python3
"""
BITS-SIEM Ingestion Service
Handles syslog data collection, normalization, and forwarding to processing layer
"""

import asyncio
import json
import logging
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import re
import ipaddress
from dataclasses import dataclass, asdict
from enum import Enum

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis
from kafka import KafkaProducer
from loguru import logger
import psycopg2
from psycopg2.extras import RealDictCursor
import socketio

# Configure logging
logger.remove()
logger.add(
    "logs/ingestion.log",
    rotation="100 MB",
    retention="30 days",
    level="INFO",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)
logger.add(lambda msg: print(msg, end=""), level="INFO")

# Configuration
class Config:
    REDIS_HOST = "redis"  # Will be updated to use Redis service
    REDIS_PORT = 6379
    KAFKA_BOOTSTRAP_SERVERS = "kafka:9092"  # Will be updated to use Kafka service
    DATABASE_URL = "postgresql://siem:siempassword@db:5432/siemdb"
    SYSLOG_PORT = 514
    SYSLOG_HOST = "0.0.0.0"
    MAX_MESSAGE_SIZE = 8192
    BATCH_SIZE = 100
    BATCH_TIMEOUT = 5  # seconds

class LogSeverity(Enum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7

class LogFacility(Enum):
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23

@dataclass
class SyslogMessage:
    """Normalized syslog message structure"""
    timestamp: datetime
    facility: str
    severity: str
    hostname: str
    app_name: str
    proc_id: str
    msg_id: str
    message: str
    raw_message: str
    source_ip: str
    source_port: int
    tenant_id: Optional[str] = None
    normalized: bool = False
    parsed_fields: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "facility": self.facility,
            "severity": self.severity,
            "hostname": self.hostname,
            "app_name": self.app_name,
            "proc_id": self.proc_id,
            "msg_id": self.msg_id,
            "message": self.message,
            "raw_message": self.raw_message,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "tenant_id": self.tenant_id,
            "normalized": self.normalized,
            "parsed_fields": self.parsed_fields or {}
        }

class SyslogParser:
    """Parse and normalize syslog messages"""
    
    # RFC 3164 syslog format regex
    RFC3164_PATTERN = re.compile(
        r'^<(\d+)>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^:]+):\s*(.*)$'
    )
    
    # RFC 5424 syslog format regex
    RFC5424_PATTERN = re.compile(
        r'^<(\d+)>(\d)\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]*)\s+(.*)$'
    )
    
    # Common log patterns for different devices
    CISCO_PATTERN = re.compile(
        r'^(\d{3}) (\w{3} \d{2} \d{2}:\d{2}:\d{2}): %([^:]+): ([^:]+): ([^:]+): (.+)$'
    )
    
    FIREWALL_PATTERN = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([^:]+): ([^:]+): ([^:]+): (.+)$'
    )
    
    @staticmethod
    def parse_priority(priority: int) -> tuple:
        """Parse syslog priority into facility and severity"""
        facility = priority >> 3
        severity = priority & 0x07
        return facility, severity
    
    @staticmethod
    def get_facility_name(facility: int) -> str:
        """Get facility name from facility number"""
        try:
            return LogFacility(facility).name
        except ValueError:
            return f"UNKNOWN({facility})"
    
    @staticmethod
    def get_severity_name(severity: int) -> str:
        """Get severity name from severity number"""
        try:
            return LogSeverity(severity).name
        except ValueError:
            return f"UNKNOWN({severity})"
    
    @classmethod
    def parse_rfc3164(cls, message: str, source_ip: str, source_port: int) -> Optional[SyslogMessage]:
        """Parse RFC 3164 format syslog message"""
        match = cls.RFC3164_PATTERN.match(message)
        if not match:
            return None
        
        priority, timestamp_str, hostname, msg = match.groups()
        priority = int(priority)
        facility_num, severity_num = cls.parse_priority(priority)
        
        # Parse timestamp
        try:
            # Add current year if not present
            if len(timestamp_str.split()) == 2:
                current_year = datetime.now().year
                timestamp_str = f"{timestamp_str} {current_year}"
            
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            timestamp = datetime.now(timezone.utc)
        
        return SyslogMessage(
            timestamp=timestamp,
            facility=cls.get_facility_name(facility_num),
            severity=cls.get_severity_name(severity_num),
            hostname=hostname.strip(),
            app_name="",
            proc_id="",
            msg_id="",
            message=msg.strip(),
            raw_message=message,
            source_ip=source_ip,
            source_port=source_port,
            parsed_fields={"format": "RFC3164"}
        )
    
    @classmethod
    def parse_rfc5424(cls, message: str, source_ip: str, source_port: int) -> Optional[SyslogMessage]:
        """Parse RFC 5424 format syslog message"""
        match = cls.RFC5424_PATTERN.match(message)
        if not match:
            return None
        
        priority, version, timestamp_str, hostname, app_name, proc_id, msg_id, structured_data, msg = match.groups()
        priority = int(priority)
        facility_num, severity_num = cls.parse_priority(priority)
        
        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            timestamp = datetime.now(timezone.utc)
        
        return SyslogMessage(
            timestamp=timestamp,
            facility=cls.get_facility_name(facility_num),
            severity=cls.get_severity_name(severity_num),
            hostname=hostname,
            app_name=app_name,
            proc_id=proc_id,
            msg_id=msg_id,
            message=msg,
            raw_message=message,
            source_ip=source_ip,
            source_port=source_port,
            parsed_fields={
                "format": "RFC5424",
                "version": version,
                "structured_data": structured_data
            }
        )
    
    @classmethod
    def parse_cisco(cls, message: str, source_ip: str, source_port: int) -> Optional[SyslogMessage]:
        """Parse Cisco device syslog message"""
        match = cls.CISCO_PATTERN.match(message)
        if not match:
            return None
        
        level, timestamp_str, facility, severity, component, msg = match.groups()
        
        # Parse timestamp
        try:
            current_year = datetime.now().year
            timestamp_str = f"{timestamp_str} {current_year}"
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            timestamp = datetime.now(timezone.utc)
        
        return SyslogMessage(
            timestamp=timestamp,
            facility=facility.upper(),
            severity=severity.upper(),
            hostname="",  # Will be filled from source
            app_name=component,
            proc_id="",
            msg_id="",
            message=msg,
            raw_message=message,
            source_ip=source_ip,
            source_port=source_port,
            parsed_fields={"format": "CISCO", "level": level}
        )
    
    @classmethod
    def parse_message(cls, message: str, source_ip: str, source_port: int) -> SyslogMessage:
        """Parse syslog message using multiple formats"""
        message = message.strip()
        
        # Try different parsers
        parsers = [
            cls.parse_rfc5424,
            cls.parse_rfc3164,
            cls.parse_cisco,
        ]
        
        for parser in parsers:
            result = parser(message, source_ip, source_port)
            if result:
                result.normalized = True
                return result
        
        # Fallback: create basic message
        return SyslogMessage(
            timestamp=datetime.now(timezone.utc),
            facility="UNKNOWN",
            severity="INFO",
            hostname="",
            app_name="",
            proc_id="",
            msg_id="",
            message=message,
            raw_message=message,
            source_ip=source_ip,
            source_port=source_port,
            parsed_fields={"format": "UNKNOWN"}
        )

class TenantResolver:
    """Resolve tenant ID from source IP"""
    
    def __init__(self, db_connection):
        self.db_connection = db_connection
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    def get_tenant_for_source(self, source_ip: str) -> Optional[str]:
        """Get tenant ID for a source IP"""
        # Check cache first
        if source_ip in self.cache:
            cached_data = self.cache[source_ip]
            if time.time() - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['tenant_id']
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT tenant_id FROM sources 
                    WHERE ip = %s OR %s::inet << ip::inet
                """, (source_ip, source_ip))
                result = cursor.fetchone()
                
                tenant_id = result['tenant_id'] if result else None
                
                # Cache the result
                self.cache[source_ip] = {
                    'tenant_id': tenant_id,
                    'timestamp': time.time()
                }
                
                return tenant_id
        except Exception as e:
            logger.error(f"Error resolving tenant for {source_ip}: {e}")
            return None

class MessageProcessor:
    """Process and forward syslog messages"""
    
    def __init__(self):
        self.redis_client = None
        self.kafka_producer = None
        self.db_connection = None
        self.tenant_resolver = None
        self.message_buffer = []
        self.last_flush = time.time()
        
    async def initialize(self):
        """Initialize connections"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=5
            )
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
        
        try:
            # Initialize Kafka producer
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=Config.KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                retries=3,
                acks='all'
            )
            logger.info("Kafka producer initialized")
        except Exception as e:
            logger.warning(f"Kafka connection failed: {e}")
            self.kafka_producer = None
        
        try:
            # Initialize database connection
            self.db_connection = psycopg2.connect(Config.DATABASE_URL)
            self.tenant_resolver = TenantResolver(self.db_connection)
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            self.db_connection = None
    
    def process_message(self, raw_message: str, source_ip: str, source_port: int):
        """Process a single syslog message"""
        try:
            # Parse the message
            parsed_message = SyslogParser.parse_message(raw_message, source_ip, source_port)
            
            # Resolve tenant
            if self.tenant_resolver:
                parsed_message.tenant_id = self.tenant_resolver.get_tenant_for_source(source_ip)
            
            # Add to buffer
            self.message_buffer.append(parsed_message)
            
            # Check if we should flush
            if (len(self.message_buffer) >= Config.BATCH_SIZE or 
                time.time() - self.last_flush >= Config.BATCH_TIMEOUT):
                self.flush_buffer()
                
        except Exception as e:
            logger.error(f"Error processing message from {source_ip}:{source_port}: {e}")
    
    def flush_buffer(self):
        """Flush message buffer to storage and processing"""
        if not self.message_buffer:
            return
        
        messages = self.message_buffer.copy()
        self.message_buffer.clear()
        self.last_flush = time.time()
        
        # Process messages asynchronously
        asyncio.create_task(self._async_flush(messages))
    
    async def _async_flush(self, messages: List[SyslogMessage]):
        """Asynchronously flush messages to storage and processing"""
        try:
            # Store in Redis for real-time access
            if self.redis_client:
                for msg in messages:
                    key = f"syslog:{msg.tenant_id}:{msg.timestamp.timestamp()}"
                    self.redis_client.setex(
                        key,
                        3600,  # 1 hour TTL
                        json.dumps(msg.to_dict())
                    )
            
            # Send to Kafka for processing
            if self.kafka_producer:
                for msg in messages:
                    topic = f"syslog.{msg.tenant_id}" if msg.tenant_id else "syslog.unknown"
                    self.kafka_producer.send(
                        topic,
                        value=msg.to_dict(),
                        key=msg.source_ip.encode('utf-8')
                    )
                self.kafka_producer.flush()
            
            # Store in database
            if self.db_connection:
                await self._store_in_database(messages)
            
            logger.info(f"Flushed {len(messages)} messages")
            
        except Exception as e:
            logger.error(f"Error flushing messages: {e}")
    
    async def _store_in_database(self, messages: List[SyslogMessage]):
        """Store messages in database"""
        try:
            with self.db_connection.cursor() as cursor:
                for msg in messages:
                    cursor.execute("""
                        INSERT INTO syslog_events (
                            timestamp, facility, severity, hostname, app_name,
                            proc_id, msg_id, message, raw_message, source_ip,
                            source_port, tenant_id, parsed_fields
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        msg.timestamp,
                        msg.facility,
                        msg.severity,
                        msg.hostname,
                        msg.app_name,
                        msg.proc_id,
                        msg.msg_id,
                        msg.message,
                        msg.raw_message,
                        msg.source_ip,
                        msg.source_port,
                        msg.tenant_id,
                        json.dumps(msg.parsed_fields or {})
                    ))
                self.db_connection.commit()
        except Exception as e:
            logger.error(f"Error storing messages in database: {e}")
            self.db_connection.rollback()

class SyslogServer:
    """UDP syslog server"""
    
    def __init__(self, host: str, port: int, processor: MessageProcessor):
        self.host = host
        self.port = port
        self.processor = processor
        self.socket = None
        self.running = False
    
    async def start(self):
        """Start the syslog server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.socket.setblocking(False)
            self.running = True
            
            logger.info(f"Syslog server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    # Use asyncio to handle non-blocking socket
                    loop = asyncio.get_event_loop()
                    data, addr = await loop.sock_recvfrom(self.socket, Config.MAX_MESSAGE_SIZE)
                    
                    if data:
                        message = data.decode('utf-8', errors='ignore')
                        self.processor.process_message(message, addr[0], addr[1])
                        
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error receiving syslog message: {e}")
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Error starting syslog server: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def stop(self):
        """Stop the syslog server"""
        self.running = False
        if self.socket:
            self.socket.close()

# FastAPI app for monitoring and management
app = FastAPI(title="BITS-SIEM Ingestion Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
processor = MessageProcessor()
syslog_server = None

class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    uptime: float
    messages_processed: int
    redis_connected: bool
    kafka_connected: bool
    database_connected: bool

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global processor, syslog_server
    
    logger.info("Starting BITS-SIEM Ingestion Service")
    
    # Initialize processor
    await processor.initialize()
    
    # Start syslog server
    syslog_server = SyslogServer(Config.SYSLOG_HOST, Config.SYSLOG_PORT, processor)
    asyncio.create_task(syslog_server.start())

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global syslog_server
    
    logger.info("Shutting down BITS-SIEM Ingestion Service")
    
    if syslog_server:
        syslog_server.stop()
    
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
        messages_processed=len(processor.message_buffer),
        redis_connected=processor.redis_client is not None,
        kafka_connected=processor.kafka_producer is not None,
        database_connected=processor.db_connection is not None
    )

@app.post("/flush")
async def flush_messages():
    """Manually flush message buffer"""
    processor.flush_buffer()
    return {"message": "Buffer flushed", "count": len(processor.message_buffer)}

@app.get("/stats")
async def get_stats():
    """Get ingestion statistics"""
    stats = {
        "buffer_size": len(processor.message_buffer),
        "last_flush": processor.last_flush,
        "connections": {
            "redis": processor.redis_client is not None,
            "kafka": processor.kafka_producer is not None,
            "database": processor.db_connection is not None
        }
    }
    return stats

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        access_log=False
    ) 
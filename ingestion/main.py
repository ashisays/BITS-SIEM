#!/usr/bin/env python3
"""
BITS-SIEM Ingestion Service
Main application for multi-protocol syslog ingestion with tenant isolation
"""

import asyncio
import json
import logging
import signal
import sys
from datetime import datetime
from typing import List, Dict, Any
import structlog
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import uvloop

from config import config
from parsers import SyslogMessage, parser
from enrichment import enricher
from listeners import ListenerManager
from database import db_manager

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Prometheus metrics
MESSAGES_RECEIVED = Counter('siem_ingestion_messages_received_total', 'Total messages received', ['tenant_id', 'protocol'])
MESSAGES_PROCESSED = Counter('siem_ingestion_messages_processed_total', 'Total messages processed', ['tenant_id', 'status'])
MESSAGES_STORED = Counter('siem_ingestion_messages_stored_total', 'Total messages stored', ['tenant_id'])
PROCESSING_TIME = Histogram('siem_ingestion_processing_seconds', 'Message processing time', ['tenant_id'])
ACTIVE_CONNECTIONS = Gauge('siem_ingestion_active_connections', 'Active connections', ['protocol'])
BATCH_SIZE = Gauge('siem_ingestion_batch_size', 'Current batch size')

class MessageProcessor:
    """Handles message processing and batching"""
    
    def __init__(self):
        self.batch_queue = []
        self.last_batch_time = datetime.utcnow()
        self.processing_lock = asyncio.Lock()
        self.stats = {
            'total_processed': 0,
            'batch_processed': 0,
            'processing_errors': 0,
            'database_errors': 0
        }
    
    async def process_message(self, message: SyslogMessage):
        """Process a single syslog message"""
        start_time = datetime.utcnow()
        
        try:
            # Update metrics
            MESSAGES_RECEIVED.labels(
                tenant_id=message.tenant_id or 'unknown',
                protocol='syslog'
            ).inc()
            
            # Add to batch queue
            async with self.processing_lock:
                self.batch_queue.append(message)
                
                # Process batch if conditions are met
                if (len(self.batch_queue) >= config.batch_size or 
                    (datetime.utcnow() - self.last_batch_time).total_seconds() >= config.batch_timeout):
                    await self._process_batch()
            
            # Update processing metrics
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            PROCESSING_TIME.labels(tenant_id=message.tenant_id or 'unknown').observe(processing_time)
            
            self.stats['total_processed'] += 1
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error processing message: {e}", tenant_id=message.tenant_id)
            
            MESSAGES_PROCESSED.labels(
                tenant_id=message.tenant_id or 'unknown',
                status='error'
            ).inc()
    
    async def _process_batch(self):
        """Process a batch of messages"""
        if not self.batch_queue:
            return
        
        batch = self.batch_queue.copy()
        self.batch_queue.clear()
        self.last_batch_time = datetime.utcnow()
        
        try:
            # Update batch size metric
            BATCH_SIZE.set(len(batch))
            
            # Store batch in database
            success = db_manager.store_messages_batch(batch)
            
            if success:
                # Publish messages to Redis streams for processing service
                await self._publish_to_streams(batch)
                
                # Update metrics for successful processing
                for message in batch:
                    MESSAGES_PROCESSED.labels(
                        tenant_id=message.tenant_id or 'unknown',
                        status='success'
                    ).inc()
                    
                    MESSAGES_STORED.labels(
                        tenant_id=message.tenant_id or 'unknown'
                    ).inc()
                
                self.stats['batch_processed'] += 1
                logger.info(f"Processed batch of {len(batch)} messages")
            else:
                # Update metrics for failed processing
                for message in batch:
                    MESSAGES_PROCESSED.labels(
                        tenant_id=message.tenant_id or 'unknown',
                        status='database_error'
                    ).inc()
                
                self.stats['database_errors'] += 1
                logger.error(f"Failed to store batch of {len(batch)} messages")
            
        except Exception as e:
            self.stats['database_errors'] += 1
            logger.error(f"Error processing batch: {e}")
    
    async def _publish_to_streams(self, messages):
        """Publish messages to Redis streams for processing service"""
        try:
            # Get Redis client from enricher
            redis_client = enricher.redis_client
            if not redis_client:
                logger.warning("Redis client not available for stream publishing")
                return
            
            # Publish each message to the syslog_events stream
            for message in messages:
                # Extract event_type from structured data if available
                event_type = 'syslog'  # default
                if message.structured_data and 'meta' in message.structured_data:
                    meta_data = message.structured_data['meta']
                    if 'event_type' in meta_data:
                        event_type = meta_data['event_type']
                
                # Convert message to dict for stream publishing
                stream_data = {
                    'timestamp': message.timestamp.isoformat() if message.timestamp else datetime.utcnow().isoformat(),
                    'hostname': message.hostname or 'unknown',
                    'program': message.program or 'unknown',
                    'message': message.message or '',
                    'facility': str(message.facility) if message.facility is not None else '16',
                    'severity': str(message.severity) if message.severity is not None else '6',
                    'tenant_id': message.tenant_id or 'demo-org',
                    'source_ip': message.source_ip or 'unknown',
                    'event_type': event_type,
                    'raw_message': message.raw_message or '',
                    'structured_data': json.dumps(message.structured_data) if message.structured_data else '{}'
                }
                
                # Add to Redis stream (matching processing service expectation)
                redis_client.xadd('siem:raw_messages', stream_data)
            
            logger.debug(f"Published {len(messages)} messages to Redis streams")
            
        except Exception as e:
            logger.error(f"Failed to publish messages to Redis streams: {e}")
    
    async def flush(self):
        """Flush any remaining messages in the queue"""
        async with self.processing_lock:
            if self.batch_queue:
                await self._process_batch()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics"""
        return {
            'processor': self.stats.copy(),
            'queue_size': len(self.batch_queue),
            'parser': parser.get_stats(),
            'enricher': enricher.get_stats(),
            'database': db_manager.get_stats()
        }

class IngestionService:
    """Main ingestion service"""
    
    def __init__(self):
        self.processor = MessageProcessor()
        self.listener_manager = ListenerManager(self.processor.process_message)
        self.running = False
        self.start_time = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(self.shutdown())
    
    async def start(self):
        """Start the ingestion service"""
        self.start_time = datetime.utcnow()
        
        try:
            logger.info("Starting BITS-SIEM Ingestion Service")
            
            # Validate configuration
            self._validate_config()
            
            # Start metrics server
            if config.metrics_enabled:
                start_http_server(config.metrics_port)
                logger.info(f"Metrics server started on port {config.metrics_port}")
            
            # Create and start listeners
            self.listener_manager.create_listeners()
            await self.listener_manager.start_all()
            
            # Start periodic tasks
            asyncio.create_task(self._periodic_flush())
            asyncio.create_task(self._periodic_stats())
            
            self.running = True
            logger.info("Ingestion service started successfully")
            
            # Keep the service running
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start ingestion service: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown the ingestion service"""
        logger.info("Shutting down ingestion service...")
        
        self.running = False
        
        try:
            # Stop listeners
            await self.listener_manager.stop_all()
            
            # Flush remaining messages
            await self.processor.flush()
            
            # Close enricher connections
            enricher.close()
            
            logger.info("Ingestion service shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        
        # Exit the process
        sys.exit(0)
    
    async def _periodic_flush(self):
        """Periodically flush messages to ensure timely processing"""
        while self.running:
            try:
                await asyncio.sleep(config.batch_timeout)
                await self.processor.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")
    
    async def _periodic_stats(self):
        """Periodically log statistics"""
        while self.running:
            try:
                await asyncio.sleep(60)  # Log stats every minute
                
                stats = self.get_stats()
                logger.info("Service statistics", **stats)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error logging stats: {e}")
    
    def _validate_config(self):
        """Validate service configuration"""
        # Check that at least one listener is enabled
        if not config.get_enabled_listeners():
            raise ValueError("No syslog listeners enabled")
        
        # Check database connectivity
        if not db_manager.health_check():
            raise ValueError("Database connection failed")
        
        # Check TLS configuration if enabled
        if config.syslog_listeners["tls"].enabled and not config.is_tls_enabled():
            raise ValueError("TLS enabled but certificates not found")
        
        logger.info("Configuration validation passed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive service statistics"""
        uptime = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'service': {
                'name': config.service_name,
                'version': '1.0.0',
                'uptime_seconds': uptime,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'running': self.running
            },
            'listeners': self.listener_manager.get_stats(),
            'processing': self.processor.get_stats(),
            'config': {
                'enabled_protocols': [l.protocol for l in config.get_enabled_listeners()],
                'batch_size': config.batch_size,
                'batch_timeout': config.batch_timeout,
                'max_workers': config.max_workers
            }
        }

async def main():
    """Main entry point"""
    try:
        # Set up async event loop
        if sys.platform != 'win32':
            uvloop.install()
        
        # Create and start the ingestion service
        service = IngestionService()
        await service.start()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the service
    asyncio.run(main())

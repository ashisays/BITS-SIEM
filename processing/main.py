"""
BITS-SIEM Processing Service
Main application for stream processing, threat detection, and alert management
"""

import asyncio
import logging
import signal
import sys
from typing import List, Dict, Any
from datetime import datetime
import structlog
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import uvloop
import json
import socket
import threading

from config import config
from stream_processor import StreamProcessor, ProcessedEvent
from threat_detection import threat_detector
from threat_models import ThreatAlert
from alert_manager import alert_manager

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
EVENTS_PROCESSED = Counter(
    'siem_events_processed_total',
    'Total number of events processed',
    ['tenant_id', 'event_type', 'source']
)

THREATS_DETECTED = Counter(
    'siem_threats_detected_total',
    'Total number of threats detected',
    ['tenant_id', 'threat_type', 'severity']
)

ALERTS_CREATED = Counter(
    'siem_alerts_created_total',
    'Total number of alerts created',
    ['tenant_id', 'alert_type', 'severity']
)

PROCESSING_DURATION = Histogram(
    'siem_processing_duration_seconds',
    'Time spent processing events',
    ['tenant_id', 'processing_stage']
)

ACTIVE_STREAMS = Gauge(
    'siem_active_streams',
    'Number of active processing streams',
    ['tenant_id', 'stream_type']
)

PROCESSING_ERRORS = Counter(
    'siem_processing_errors_total',
    'Total number of processing errors',
    ['tenant_id', 'error_type']
)

class ProcessingService:
    """Main processing service orchestrator"""
    
    def __init__(self):
        self.stream_processor = None
        self.running = False
        self.health_server = None
        self.health_thread = None
        self.stats = {
            'start_time': datetime.utcnow(),
            'events_processed': 0,
            'threats_detected': 0,
            'alerts_created': 0,
            'processing_errors': 0
        }
        self.tasks = []
        
        # Initialize components
        self._init_components()
    
    def _init_components(self):
        """Initialize all processing components"""
        try:
            # Initialize stream processor
            self.stream_processor = StreamProcessor()
            
            # Initialize threat detection manager
            threat_detector.stats['start_time'] = datetime.utcnow()
            
            # Initialize alert manager (will be done in async context)
            # Redis initialization will happen when the event loop starts
            
            logger.info("Processing service components initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    async def start(self):
        """Start the processing service"""
        try:
            self.running = True
            logger.info("Starting BITS-SIEM Processing Service")
            
            # Start Prometheus metrics server
            start_http_server(config.metrics_port)
            logger.info(f"Metrics server started on port {config.metrics_port}")
            
            # Start health check HTTP server
            self.start_health_server()
            
            # Initialize alert manager
            await alert_manager.initialize()
            logger.info("Alert manager initialized")
            
            # Initialize stream processor
            await self.stream_processor.initialize()
            logger.info("Stream processor initialized")
            
            # Start stream processor
            await self.stream_processor.start(self._process_events)
            logger.info("Stream processor started")
            
            # Start threat detection cleanup task
            cleanup_task = asyncio.create_task(threat_detector.start_cleanup_task())
            self.tasks.append(cleanup_task)
            
            # Note: Stream processor handles message processing via start() method
            # No additional processing loop needed
            
            # Start health check task
            health_task = asyncio.create_task(self._health_check_loop())
            self.tasks.append(health_task)
            
            # Start metrics collection task
            metrics_task = asyncio.create_task(self._metrics_collection_loop())
            self.tasks.append(metrics_task)
            
            logger.info("Processing service started successfully")
            
            # Wait for all tasks to complete
            await asyncio.gather(*self.tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Error starting processing service: {e}")
            raise
    
    # _processing_loop method removed - StreamProcessor.start() handles message processing
    
    async def _process_events(self, events: List[ProcessedEvent]):
        """Process a batch of events"""
        try:
            with PROCESSING_DURATION.labels(
                tenant_id="batch",
                processing_stage="full_pipeline"
            ).time():
                
                # Process each event
                for event in events:
                    await self._process_single_event(event)
                
                self.stats['events_processed'] += len(events)
                
                # Update active streams metric
                ACTIVE_STREAMS.labels(
                    tenant_id="all",
                    stream_type="processing"
                ).set(len(events))
                
        except Exception as e:
            logger.error(f"Error processing event batch: {e}")
            self.stats['processing_errors'] += 1
            PROCESSING_ERRORS.labels(
                tenant_id="unknown",
                error_type="batch_processing"
            ).inc()
    
    async def _process_single_event(self, event: ProcessedEvent):
        """Process a single event through the threat detection pipeline"""
        try:
            # Update metrics
            EVENTS_PROCESSED.labels(
                tenant_id=event.tenant_id,
                event_type=event.event_type,
                source=event.source_ip
            ).inc()
            
            # Run threat detection
            with PROCESSING_DURATION.labels(
                tenant_id=event.tenant_id,
                processing_stage="threat_detection"
            ).time():
                
                threat_alerts = await threat_detector.analyze_event(event)
            
            # Process any detected threats
            if threat_alerts:
                logger.info(f"🚨 Threat detected! Processing {len(threat_alerts)} alerts for tenant {event.tenant_id}")
                await self._process_threat_alerts(threat_alerts)
            
            # Log event processing with INFO level for debugging
            logger.info(
                f"Event processed: tenant={event.tenant_id}, type={event.event_type}, "
                f"source={event.source_ip}, threats={len(threat_alerts) if threat_alerts else 0}"
            )
            
        except Exception as e:
            logger.error(f"Error processing single event: {e}")
            self.stats['processing_errors'] += 1
            PROCESSING_ERRORS.labels(
                tenant_id=event.tenant_id if hasattr(event, 'tenant_id') else "unknown",
                error_type="single_event"
            ).inc()
    
    async def _process_threat_alerts(self, threat_alerts: List[ThreatAlert]):
        """Process detected threat alerts"""
        try:
            for alert in threat_alerts:
                # Update metrics
                THREATS_DETECTED.labels(
                    tenant_id=alert.tenant_id,
                    threat_type=alert.alert_type,
                    severity=alert.severity
                ).inc()
                
                # Process alert through alert manager
                with PROCESSING_DURATION.labels(
                    tenant_id=alert.tenant_id,
                    processing_stage="alert_management"
                ).time():
                    
                    managed_alert = await alert_manager.process_threat_alert(alert)
                
                if managed_alert:
                    ALERTS_CREATED.labels(
                        tenant_id=alert.tenant_id,
                        alert_type=alert.alert_type,
                        severity=alert.severity
                    ).inc()
                    
                    self.stats['alerts_created'] += 1
                    
                    logger.warning(
                        "Threat alert processed",
                        tenant_id=alert.tenant_id,
                        alert_type=alert.alert_type,
                        severity=alert.severity,
                        source_ip=alert.source_ip,
                        risk_score=alert.risk_score
                    )
                
                self.stats['threats_detected'] += 1
                
        except Exception as e:
            logger.error(f"Error processing threat alerts: {e}")
            self.stats['processing_errors'] += 1
            PROCESSING_ERRORS.labels(
                tenant_id="unknown",
                error_type="threat_alert_processing"
            ).inc()
    
    async def _health_check_loop(self):
        """Health check monitoring loop"""
        while self.running:
            try:
                # Check component health
                health_status = await self._check_component_health()
                
                # Log health status
                logger.info(
                    "Health check completed",
                    **health_status
                )
                
                # Wait before next check
                await asyncio.sleep(config.monitoring.health_check_interval)
                
            except asyncio.CancelledError:
                logger.info("Health check loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in health check: {e}")
                await asyncio.sleep(30)  # Wait on error
    
    async def _check_component_health(self) -> Dict[str, Any]:
        """Check health of all components"""
        health_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'components': {}
        }
        
        try:
            # Check stream processor
            if self.stream_processor:
                stream_stats = self.stream_processor.get_stats()
                health_status['components']['stream_processor'] = {
                    'status': 'healthy' if stream_stats['events_processed'] >= 0 else 'unhealthy',
                    'stats': stream_stats
                }
            
            # Check threat detector
            threat_stats = threat_detector.get_stats()
            health_status['components']['threat_detector'] = {
                'status': 'healthy' if threat_stats['total_events_processed'] >= 0 else 'unhealthy',
                'stats': threat_stats
            }
            
            # Check alert manager
            alert_stats = alert_manager.get_stats()
            health_status['components']['alert_manager'] = {
                'status': 'healthy' if alert_stats['alerts_created'] >= 0 else 'unhealthy',
                'stats': alert_stats
            }
            
            # Check for any unhealthy components
            for component, status in health_status['components'].items():
                if status['status'] != 'healthy':
                    health_status['overall_status'] = 'degraded'
                    break
            
        except Exception as e:
            logger.error(f"Error checking component health: {e}")
            health_status['overall_status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status
    
    def _simple_health_server(self):
        """Simple HTTP server for health checks"""
        import http.server
        import socketserver
        
        class HealthHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    try:
                        # Simple health check - just return OK if service is running
                        health_data = {
                            'status': 'healthy',
                            'timestamp': datetime.utcnow().isoformat(),
                            'service': 'bits-siem-processing'
                        }
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(health_data).encode())
                    except Exception as e:
                        self.send_response(503)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        error_data = {
                            'status': 'unhealthy',
                            'error': str(e),
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        self.wfile.write(json.dumps(error_data).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                # Suppress default logging
                pass
        
        try:
            with socketserver.TCPServer(("", 8082), HealthHandler) as httpd:
                self.health_server = httpd
                logger.info("Health check server started on port 8082")
                httpd.serve_forever()
        except Exception as e:
            logger.error(f"Health server error: {e}")
    
    def start_health_server(self):
        """Start health server in background thread"""
        try:
            self.health_thread = threading.Thread(target=self._simple_health_server, daemon=True)
            self.health_thread.start()
        except Exception as e:
            logger.error(f"Failed to start health server: {e}")
    
    def stop_health_server(self):
        """Stop health server"""
        try:
            if self.health_server:
                self.health_server.shutdown()
                logger.info("Health server stopped")
        except Exception as e:
            logger.error(f"Error stopping health server: {e}")
    
    async def _metrics_collection_loop(self):
        """Collect and update metrics periodically"""
        while self.running:
            try:
                # Update service stats
                uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds()
                
                # Update gauges
                ACTIVE_STREAMS.labels(
                    tenant_id="service",
                    stream_type="uptime"
                ).set(uptime)
                
                # Wait before next collection
                await asyncio.sleep(config.monitoring.metrics_collection_interval)
                
            except asyncio.CancelledError:
                logger.info("Metrics collection loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(60)  # Wait on error
    
    async def stop(self):
        """Stop the processing service gracefully"""
        logger.info("Stopping processing service...")
        
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Stop components
        if self.stream_processor:
            await self.stream_processor.stop()
        
        await threat_detector.stop()
        
        # Stop health server
        self.stop_health_server()
        
        logger.info("Processing service stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        stats = self.stats.copy()
        stats['uptime_seconds'] = (datetime.utcnow() - stats['start_time']).total_seconds()
        stats['start_time'] = stats['start_time'].isoformat()
        
        # Add component stats
        stats['components'] = {
            'stream_processor': self.stream_processor.get_stats() if self.stream_processor else {},
            'threat_detector': threat_detector.get_stats(),
            'alert_manager': alert_manager.get_stats()
        }
        
        return stats

# Global processing service instance
processing_service = ProcessingService()

async def main():
    """Main entry point"""
    
    # Set up signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(processing_service.stop())
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Use uvloop for better performance
        uvloop.install()
        
        # Start the processing service
        await processing_service.start()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        await processing_service.stop()

if __name__ == "__main__":
    # Configure logging level
    log_level = getattr(config, 'log_level', 'INFO')
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(message)s'
    )
    
    # Run the service
    asyncio.run(main())

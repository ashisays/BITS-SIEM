#!/usr/bin/env python3
"""
BITS-SIEM Enhanced Notification Service
======================================

Comprehensive notification system supporting:
- Real-time WebSocket notifications
- Email notifications with templates
- Webhook integrations
- Notification preferences and escalation
- Rate limiting and deduplication
"""

import asyncio
import json
import logging
import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
import structlog
import redis.asyncio as aioredis
import aiohttp
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

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

@dataclass
class NotificationTemplate:
    """Email notification template"""
    name: str
    subject: str
    html_body: str
    text_body: str
    variables: List[str]

@dataclass
class NotificationPreferences:
    """User notification preferences"""
    user_id: str
    tenant_id: str
    email_enabled: bool = True
    webhook_enabled: bool = False
    webhook_url: Optional[str] = None
    email_frequency: str = "immediate"  # immediate, hourly, daily
    severity_threshold: str = "low"  # low, medium, high, critical
    quiet_hours_start: Optional[str] = None  # HH:MM
    quiet_hours_end: Optional[str] = None  # HH:MM
    escalation_enabled: bool = True
    escalation_delay_minutes: int = 30

@dataclass
class NotificationMessage:
    """Notification message structure"""
    id: str
    tenant_id: str
    user_id: Optional[str]
    type: str  # security_alert, system_notification, etc.
    severity: str
    title: str
    message: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    alert_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    created_at: datetime = None
    sent_at: Optional[datetime] = None
    delivery_status: str = "pending"  # pending, sent, failed, delivered
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        elif isinstance(self.created_at, str):
            try:
                # Parse ISO format string to datetime
                self.created_at = datetime.fromisoformat(self.created_at.replace('Z', '+00:00'))
            except ValueError:
                # If parsing fails, use current time
                self.created_at = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        if isinstance(data.get('created_at'), datetime):
            data['created_at'] = self.created_at.isoformat()
        if isinstance(data.get('sent_at'), datetime):
            data['sent_at'] = self.sent_at.isoformat()
        return data

class EmailNotificationService:
    """Handles email notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.smtp_server = config.get('smtp_server', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.use_tls = config.get('use_tls', True)
        self.from_email = config.get('from_email', 'siem@company.com')
        self.from_name = config.get('from_name', 'BITS-SIEM Security')
        
        # Load email templates
        self.templates = self._load_email_templates()
    
    def _load_email_templates(self) -> Dict[str, NotificationTemplate]:
        """Load email notification templates"""
        templates = {}
        
        # Brute force attack template
        templates['brute_force_attack'] = NotificationTemplate(
            name='brute_force_attack',
            subject='🚨 SECURITY ALERT: Brute Force Attack Detected',
            html_body="""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: #dc3545; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h1 style="margin: 0; font-size: 24px;">🚨 Security Alert</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Brute Force Attack Detected</p>
                    </div>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h2 style="margin: 0 0 15px 0; color: #dc3545;">Attack Details</h2>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Source IP:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{source_ip}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Target Username:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{username}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Failed Attempts:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{failed_attempts}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Time Window:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{time_window} seconds</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; font-weight: bold;">Confidence Score:</td>
                                <td style="padding: 8px 0;">{confidence_score}%</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h3 style="margin: 0 0 15px 0; color: #856404;">⚠️ Immediate Actions Required</h3>
                        <ul style="margin: 0; padding-left: 20px;">
                            <li>Block the source IP address</li>
                            <li>Review authentication logs</li>
                            <li>Check for successful intrusions</li>
                            <li>Update firewall rules if necessary</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                        <p style="margin: 0; color: #6c757d; font-size: 14px;">
                            This alert was generated by BITS-SIEM Security System<br>
                            Timestamp: {timestamp}<br>
                            Alert ID: {alert_id}
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """,
            text_body="""
🚨 SECURITY ALERT: Brute Force Attack Detected

Attack Details:
- Source IP: {source_ip}
- Target Username: {username}
- Failed Attempts: {failed_attempts}
- Time Window: {time_window} seconds
- Confidence Score: {confidence_score}%

⚠️ Immediate Actions Required:
• Block the source IP address
• Review authentication logs
• Check for successful intrusions
• Update firewall rules if necessary

This alert was generated by BITS-SIEM Security System
Timestamp: {timestamp}
Alert ID: {alert_id}
            """,
            variables=['source_ip', 'username', 'failed_attempts', 'time_window', 'confidence_score', 'timestamp', 'alert_id']
        )
        
        # Port scan template
        templates['port_scan_attack'] = NotificationTemplate(
            name='port_scan_attack',
            subject='🔍 SECURITY ALERT: Port Scanning Activity Detected',
            html_body="""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: #fd7e14; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h1 style="margin: 0; font-size: 24px;">🔍 Security Alert</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Port Scanning Activity Detected</p>
                    </div>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h2 style="margin: 0 0 15px 0; color: #fd7e14;">Scan Details</h2>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Source IP:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{source_ip}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Ports Scanned:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{ports_count}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Scan Type:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{scan_type}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6; font-weight: bold;">Time Window:</td>
                                <td style="padding: 8px 0; border-bottom: 1px solid #dee2e6;">{time_window} seconds</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; font-weight: bold;">Confidence Score:</td>
                                <td style="padding: 8px 0;">{confidence_score}%</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                        <h3 style="margin: 0 0 15px 0; color: #856404;">⚠️ Recommended Actions</h3>
                        <ul style="margin: 0; padding-left: 20px;">
                            <li>Monitor the source IP for further activity</li>
                            <li>Review firewall logs for blocked connections</li>
                            <li>Check if any services were compromised</li>
                            <li>Consider blocking the source IP if scanning continues</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                        <p style="margin: 0; color: #6c757d; font-size: 14px;">
                            This alert was generated by BITS-SIEM Security System<br>
                            Timestamp: {timestamp}<br>
                            Alert ID: {alert_id}
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """,
            text_body="""
🔍 SECURITY ALERT: Port Scanning Activity Detected

Scan Details:
- Source IP: {source_ip}
- Ports Scanned: {ports_count}
- Scan Type: {scan_type}
- Time Window: {time_window} seconds
- Confidence Score: {confidence_score}%

⚠️ Recommended Actions:
• Monitor the source IP for further activity
• Review firewall logs for blocked connections
• Check if any services were compromised
• Consider blocking the source IP if scanning continues

This alert was generated by BITS-SIEM Security System
Timestamp: {timestamp}
Alert ID: {alert_id}
            """,
            variables=['source_ip', 'ports_count', 'scan_type', 'time_window', 'confidence_score', 'timestamp', 'alert_id']
        )
        
        return templates
    
    async def send_notification(self, notification: NotificationMessage, 
                               preferences: NotificationPreferences,
                               template_data: Dict[str, Any]) -> bool:
        """Send email notification"""
        try:
            if not preferences.email_enabled:
                return False
            
            # Check quiet hours
            if self._is_in_quiet_hours(preferences):
                logger.info(f"Notification {notification.id} suppressed due to quiet hours")
                return False
            
            # Get template
            template = self.templates.get(notification.type, self.templates.get('brute_force_attack'))
            if not template:
                logger.warning(f"No template found for notification type: {notification.type}")
                return False
            
            # Format template
            subject = template.subject
            html_body = template.html_body
            text_body = template.text_body
            
            for var in template.variables:
                value = template_data.get(var, 'N/A')
                subject = subject.replace(f'{{{var}}}', str(value))
                html_body = html_body.replace(f'{{{var}}}', str(value))
                text_body = text_body.replace(f'{{{var}}}', str(value))
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = preferences.user_id  # Assuming user_id is email
            
            # Attach text and HTML parts
            text_part = MIMEText(text_body, 'plain')
            html_part = MIMEText(html_body, 'html')
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            if self.use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls(context=context)
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.send_message(msg)
            
            logger.info(f"Email notification sent for {notification.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False
    
    def _is_in_quiet_hours(self, preferences: NotificationPreferences) -> bool:
        """Check if current time is in quiet hours"""
        if not preferences.quiet_hours_start or not preferences.quiet_hours_end:
            return False
        
        try:
            now = datetime.now()
            start_time = datetime.strptime(preferences.quiet_hours_start, '%H:%M').time()
            end_time = datetime.strptime(preferences.quiet_hours_end, '%H:%M').time()
            current_time = now.time()
            
            if start_time <= end_time:
                return start_time <= current_time <= end_time
            else:  # Crosses midnight
                return current_time >= start_time or current_time <= end_time
                
        except Exception as e:
            logger.error(f"Error checking quiet hours: {e}")
            return False

class WebhookNotificationService:
    """Handles webhook notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 5)
    
    async def send_notification(self, notification: NotificationMessage,
                               preferences: NotificationPreferences) -> bool:
        """Send webhook notification"""
        try:
            if not preferences.webhook_enabled or not preferences.webhook_url:
                return False
            
            # Prepare webhook payload
            # Handle created_at which might be a string or datetime
            if isinstance(notification.created_at, str):
                timestamp = notification.created_at
            elif isinstance(notification.created_at, datetime):
                timestamp = notification.created_at.isoformat()
            else:
                timestamp = 'Unknown'
            
            payload = {
                'id': notification.id,
                'type': notification.type,
                'severity': notification.severity,
                'title': notification.title,
                'message': notification.message,
                'source_ip': notification.source_ip,
                'target_ip': notification.target_ip,
                'alert_id': notification.alert_id,
                'correlation_id': notification.correlation_id,
                'timestamp': timestamp,
                'tenant_id': notification.tenant_id,
                'metadata': notification.metadata
            }
            
            # Send webhook with retries
            for attempt in range(self.max_retries):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            preferences.webhook_url,
                            json=payload,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            headers={'Content-Type': 'application/json'}
                        ) as response:
                            if response.status in [200, 201, 202]:
                                logger.info(f"Webhook notification sent for {notification.id}")
                                return True
                            else:
                                logger.warning(f"Webhook failed with status {response.status}")
                                
                except asyncio.TimeoutError:
                    logger.warning(f"Webhook timeout on attempt {attempt + 1}")
                except Exception as e:
                    logger.warning(f"Webhook error on attempt {attempt + 1}: {e}")
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
            
            logger.error(f"Webhook notification failed after {self.max_retries} attempts")
            return False
            
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")
            return False

class WebSocketManager:
    """Manages WebSocket connections for real-time notifications"""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.connection_lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, tenant_id: str):
        """Connect a new WebSocket client"""
        await websocket.accept()
        
        async with self.connection_lock:
            if tenant_id not in self.active_connections:
                self.active_connections[tenant_id] = []
            self.active_connections[tenant_id].append(websocket)
        
        logger.info(f"WebSocket connected for tenant {tenant_id}")
    
    async def disconnect(self, websocket: WebSocket, tenant_id: str):
        """Disconnect a WebSocket client"""
        async with self.connection_lock:
            if tenant_id in self.active_connections:
                self.active_connections[tenant_id].remove(websocket)
                if not self.active_connections[tenant_id]:
                    del self.active_connections[tenant_id]
        
        logger.info(f"WebSocket disconnected for tenant {tenant_id}")
    
    async def send_notification(self, tenant_id: str, notification: Dict[str, Any]):
        """Send notification to all connected clients for a tenant"""
        if tenant_id not in self.active_connections:
            return
        
        # Create a copy of the list to avoid modification during iteration
        connections = self.active_connections[tenant_id].copy()
        
        for connection in connections:
            try:
                await connection.send_text(json.dumps(notification))
            except Exception as e:
                logger.error(f"Failed to send WebSocket notification: {e}")
                # Remove failed connection
                await self.disconnect(connection, tenant_id)

class NotificationService:
    """Main notification service"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.redis_client = None
        self.email_service = EmailNotificationService(config.get('email', {}))
        self.webhook_service = WebhookNotificationService(config.get('webhook', {}))
        self.websocket_manager = WebSocketManager()
        self.running = False
        
        # Statistics
        self.stats = {
            'notifications_processed': 0,
            'emails_sent': 0,
            'webhooks_sent': 0,
            'websocket_notifications': 0,
            'failed_notifications': 0,
            'start_time': datetime.utcnow()
        }
    
    async def initialize(self):
        """Initialize the notification service"""
        try:
            # Initialize Redis connection
            if self.config['redis'].get('password'):
                self.redis_client = aioredis.Redis(
                    host=self.config['redis']['host'],
                    port=self.config['redis']['port'],
                    db=self.config['redis'].get('db', 0),
                    password=self.config['redis'].get('password'),
                    decode_responses=True
                )
            else:
                self.redis_client = aioredis.Redis(
                    host=self.config['redis']['host'],
                    port=self.config['redis']['port'],
                    db=self.config['redis'].get('db', 0),
                    decode_responses=True
                )
            
            # Test Redis connection
            await self.redis_client.ping()
            
            # Start the notification consumer
            asyncio.create_task(self.start_notification_consumer())
            
            logger.info("Notification service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize notification service: {e}")
            raise
    
    async def process_notification(self, notification: NotificationMessage,
                                 preferences: NotificationPreferences) -> bool:
        """Process a notification through all channels"""
        try:
            self.stats['notifications_processed'] += 1
            
            # Check severity threshold
            if not self._meets_severity_threshold(notification.severity, preferences.severity_threshold):
                logger.info(f"Notification {notification.id} below severity threshold")
                return True
            
            # Send through all channels
            success = True
            
            # Email notification
            if preferences.email_enabled:
                email_sent = await self.email_service.send_notification(notification, preferences, self._get_template_data(notification))
                if email_sent:
                    self.stats['emails_sent'] += 1
                else:
                    success = False
            
            # Webhook notification
            if preferences.webhook_enabled:
                webhook_sent = await self.webhook_service.send_notification(notification, preferences)
                if webhook_sent:
                    self.stats['webhooks_sent'] += 1
                else:
                    success = False
            
            # WebSocket notification (always send for real-time updates)
            await self.websocket_manager.send_notification(notification.tenant_id, notification.to_dict())
            self.stats['websocket_notifications'] += 1
            
            if not success:
                self.stats['failed_notifications'] += 1
            
            return success
            
        except Exception as e:
            logger.error(f"Error processing notification: {e}")
            self.stats['failed_notifications'] += 1
            return False
    
    def _meets_severity_threshold(self, notification_severity: str, user_threshold: str) -> bool:
        """Check if notification meets user's severity threshold"""
        severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        notification_level = severity_levels.get(notification_severity.lower(), 1)
        threshold_level = severity_levels.get(user_threshold.lower(), 1)
        
        return notification_level >= threshold_level
    
    def _get_template_data(self, notification: NotificationMessage) -> Dict[str, Any]:
        """Extract template data from notification"""
        # Handle created_at which might be a string or datetime
        if isinstance(notification.created_at, str):
            try:
                # Parse ISO format string to datetime
                created_dt = datetime.fromisoformat(notification.created_at.replace('Z', '+00:00'))
                timestamp = created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            except ValueError:
                timestamp = notification.created_at  # Use as-is if parsing fails
        elif isinstance(notification.created_at, datetime):
            timestamp = notification.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            timestamp = 'Unknown'
        
        template_data = {
            'timestamp': timestamp,
            'alert_id': notification.alert_id or 'N/A'
        }
        
        # Extract data from metadata
        if notification.metadata:
            if 'failed_attempts' in notification.metadata:
                template_data['failed_attempts'] = notification.metadata['failed_attempts']
            if 'time_window' in notification.metadata:
                template_data['time_window'] = notification.metadata['time_window']
            if 'confidence_score' in notification.metadata:
                template_data['confidence_score'] = f"{notification.metadata['confidence_score'] * 100:.1f}"
            if 'ports_count' in notification.metadata:
                template_data['ports_count'] = notification.metadata['ports_count']
            if 'scan_type' in notification.metadata:
                template_data['scan_type'] = notification.metadata['scan_type']
        
        # Extract from message content
        if notification.source_ip:
            template_data['source_ip'] = notification.source_ip
        if notification.target_ip:
            template_data['target_ip'] = notification.target_ip
        
        # Default values
        template_data.setdefault('username', 'Unknown')
        template_data.setdefault('failed_attempts', 'Unknown')
        template_data.setdefault('time_window', 'Unknown')
        template_data.setdefault('confidence_score', 'Unknown')
        template_data.setdefault('ports_count', 'Unknown')
        template_data.setdefault('scan_type', 'Unknown')
        
        return template_data
    
    async def start_notification_consumer(self):
        """Start consuming notifications from Redis streams"""
        self.running = True
        
        while self.running:
            try:
                # Read from notification stream
                if self.redis_client:
                    notifications = await self.redis_client.xread(
                        {'notification_stream': '0'}, count=10, block=1000
                    )
                    
                    for stream, messages in notifications:
                        for message_id, fields in messages:
                            try:
                                # Parse notification
                                notification_data = json.loads(fields[b'data'].decode())
                                notification = NotificationMessage(**notification_data)
                                
                                # Get user preferences (simplified - in production, fetch from database)
                                preferences = NotificationPreferences(
                                    user_id=notification.user_id or 'admin',
                                    tenant_id=notification.tenant_id
                                )
                                
                                # Process notification
                                await self.process_notification(notification, preferences)
                                
                                # Acknowledge message
                                await self.redis_client.xack('notification_stream', 'notification_group', message_id)
                                
                            except Exception as e:
                                logger.error(f"Error processing notification message: {e}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in notification consumer: {e}")
                await asyncio.sleep(5)
    
    async def stop(self):
        """Stop the notification service"""
        self.running = False
        
        if self.redis_client:
            await self.redis_client.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        stats = self.stats.copy()
        stats['uptime_seconds'] = (datetime.utcnow() - stats['start_time']).total_seconds()
        stats['start_time'] = stats['start_time'].isoformat()
        return stats

# Configuration
import os

config = {
    'redis': {
        'host': os.getenv('REDIS_HOST', 'localhost'),
        'port': int(os.getenv('REDIS_PORT', 6379)),
        'password': os.getenv('REDIS_PASSWORD'),
        'db': int(os.getenv('REDIS_DB', 0))
    },
    'email': {
        'smtp_server': os.getenv('SMTP_SERVER', 'localhost'),
        'smtp_port': int(os.getenv('SMTP_PORT', 587)),
        'username': os.getenv('SMTP_USERNAME'),
        'password': os.getenv('SMTP_PASSWORD'),
        'use_tls': os.getenv('SMTP_USE_TLS', 'true').lower() == 'true',
        'from_email': os.getenv('EMAIL_FROM', 'siem@company.com'),
        'from_name': os.getenv('EMAIL_FROM_NAME', 'BITS-SIEM Security')
    },
    'webhook': {
        'timeout': int(os.getenv('WEBHOOK_TIMEOUT', 30)),
        'max_retries': int(os.getenv('WEBHOOK_MAX_RETRIES', 3)),
        'retry_delay': int(os.getenv('WEBHOOK_RETRY_DELAY', 5))
    }
}

# Create FastAPI app
app = FastAPI(title="BITS-SIEM Notification Service", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global notification service instance
notification_service = NotificationService(config)

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    await notification_service.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await notification_service.stop()

@app.websocket("/ws/notifications/{tenant_id}")
async def websocket_endpoint(websocket: WebSocket, tenant_id: str):
    """WebSocket endpoint for real-time notifications"""
    await notification_service.websocket_manager.connect(websocket, tenant_id)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        await notification_service.websocket_manager.disconnect(websocket, tenant_id)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "stats": notification_service.get_stats()
    }

@app.post("/notifications/send")
async def send_notification(notification_data: Dict[str, Any]):
    """Send a notification immediately"""
    try:
        notification = NotificationMessage(**notification_data)
        preferences = NotificationPreferences(
            user_id=notification.user_id or 'admin',
            tenant_id=notification.tenant_id
        )
        
        success = await notification_service.process_notification(notification, preferences)
        
        return {
            "status": "success" if success else "partial_failure",
            "notification_id": notification.id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)

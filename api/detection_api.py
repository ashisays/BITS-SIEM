"""
BITS-SIEM Detection API Endpoints
================================

FastAPI endpoints for the brute-force detection system including:
- Authentication event ingestion
- Security alert management
- Behavioral baseline configuration
- Detection rule management
- Real-time monitoring and statistics
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import logging

from database import (
    get_db, AuthenticationEvent, UserBehaviorBaseline, DetectionRule,
    SecurityAlert, CorrelationEvent, DATABASE_AVAILABLE
)
from bruteforce_detection import (
    BruteForceDetectionEngine, create_detection_engine, 
    initialize_default_detection_rules
)

logger = logging.getLogger(__name__)

# Create router
detection_router = APIRouter(prefix="/api/detection", tags=["detection"])

# Pydantic models for API requests/responses
class AuthEventRequest(BaseModel):
    """Request model for authentication event ingestion"""
    username: str = Field(..., description="Username attempting authentication")
    event_type: str = Field(..., description="Type of event: login_success, login_failure, logout")
    source_type: str = Field(..., description="Source system: web, ssh, rdp, vpn, api, etc.")
    source_ip: str = Field(..., description="Source IP address")
    source_port: Optional[int] = Field(None, description="Source port number")
    user_agent: Optional[str] = Field(None, description="User agent string")
    country: Optional[str] = Field(None, description="Country code (e.g., US, CA)")
    city: Optional[str] = Field(None, description="City name")
    device_fingerprint: Optional[str] = Field(None, description="Device fingerprint hash")
    session_id: Optional[str] = Field(None, description="Session identifier")
    login_duration: Optional[int] = Field(None, description="Login duration in seconds")
    failed_attempts_count: Optional[int] = Field(0, description="Number of failed attempts")
    time_since_last_attempt: Optional[int] = Field(None, description="Seconds since last attempt")
    metadata: Optional[Dict[str, Any]] = Field({}, description="Additional metadata")

class AlertResponse(BaseModel):
    """Response model for security alerts"""
    id: int
    alert_type: str
    title: str
    description: str
    severity: str
    confidence_score: float
    username: Optional[str]
    source_ip: Optional[str]
    affected_systems: List[str]
    status: str
    created_at: datetime
    correlation_data: Optional[Dict[str, Any]]

class BaselineResponse(BaseModel):
    """Response model for user behavior baselines"""
    id: int
    username: str
    typical_login_hours: List[int]
    typical_days: List[int]
    avg_session_duration: float
    typical_countries: List[str]
    typical_ips: List[str]
    avg_daily_logins: float
    confidence_score: float
    last_updated: datetime

class DetectionRuleRequest(BaseModel):
    """Request model for detection rule configuration"""
    rule_name: str = Field(..., description="Name of the detection rule")
    rule_type: str = Field(..., description="Type: behavioral, correlation, threshold")
    description: Optional[str] = Field(None, description="Rule description")
    is_enabled: bool = Field(True, description="Whether rule is enabled")
    severity: str = Field("medium", description="Severity: low, medium, high, critical")
    confidence_threshold: float = Field(0.7, description="Confidence threshold (0.0-1.0)")
    parameters: Dict[str, Any] = Field({}, description="Rule-specific parameters")

class DetectionRuleResponse(BaseModel):
    """Response model for detection rules"""
    id: int
    rule_name: str
    rule_type: str
    description: Optional[str]
    is_enabled: bool
    severity: str
    confidence_threshold: float
    parameters: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

class DetectionStatsResponse(BaseModel):
    """Response model for detection statistics"""
    total_events_24h: int
    total_alerts_24h: int
    active_alerts: int
    top_source_ips: List[Dict[str, Any]]
    alert_severity_breakdown: Dict[str, int]
    detection_accuracy: float

# Authentication event ingestion endpoints
@detection_router.post("/events/ingest")
async def ingest_authentication_event(
    event: AuthEventRequest,
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    """
    Ingest a new authentication event and trigger detection analysis
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        # Create detection engine
        detection_engine = create_detection_engine()
        if not detection_engine:
            raise HTTPException(status_code=503, detail="Detection engine not available")
        
        # Prepare event data
        event_data = {
            'tenant_id': tenant_id,
            'username': event.username,
            'event_type': event.event_type,
            'source_type': event.source_type,
            'source_ip': event.source_ip,
            'source_port': event.source_port,
            'user_agent': event.user_agent,
            'country': event.country,
            'city': event.city,
            'device_fingerprint': event.device_fingerprint,
            'session_id': event.session_id,
            'login_duration': event.login_duration,
            'failed_attempts_count': event.failed_attempts_count,
            'time_since_last_attempt': event.time_since_last_attempt,
            'metadata': event.metadata
        }
        
        # Process event and generate alerts
        alerts = detection_engine.process_authentication_event(event_data)
        
        return {
            "status": "success",
            "message": f"Authentication event processed successfully",
            "alerts_generated": len(alerts),
            "alert_ids": [alert.id for alert in alerts]
        }
        
    except Exception as e:
        logger.error(f"Error ingesting authentication event: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process authentication event: {str(e)}")

@detection_router.post("/events/batch-ingest")
async def batch_ingest_authentication_events(
    events: List[AuthEventRequest],
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    """
    Batch ingest multiple authentication events
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        detection_engine = create_detection_engine()
        if not detection_engine:
            raise HTTPException(status_code=503, detail="Detection engine not available")
        
        total_alerts = 0
        all_alert_ids = []
        
        for event in events:
            event_data = {
                'tenant_id': tenant_id,
                'username': event.username,
                'event_type': event.event_type,
                'source_type': event.source_type,
                'source_ip': event.source_ip,
                'source_port': event.source_port,
                'user_agent': event.user_agent,
                'country': event.country,
                'city': event.city,
                'device_fingerprint': event.device_fingerprint,
                'session_id': event.session_id,
                'login_duration': event.login_duration,
                'failed_attempts_count': event.failed_attempts_count,
                'time_since_last_attempt': event.time_since_last_attempt,
                'metadata': event.metadata
            }
            
            alerts = detection_engine.process_authentication_event(event_data)
            total_alerts += len(alerts)
            all_alert_ids.extend([alert.id for alert in alerts])
        
        return {
            "status": "success",
            "message": f"Processed {len(events)} authentication events",
            "events_processed": len(events),
            "total_alerts_generated": total_alerts,
            "alert_ids": all_alert_ids
        }
        
    except Exception as e:
        logger.error(f"Error batch ingesting authentication events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process batch events: {str(e)}")

# Security alert management endpoints
@detection_router.get("/alerts", response_model=List[AlertResponse])
async def get_security_alerts(
    tenant_id: str = Query(..., description="Tenant ID"),
    status: Optional[str] = Query(None, description="Filter by status: open, investigating, resolved, false_positive"),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    limit: int = Query(50, description="Maximum number of alerts to return"),
    offset: int = Query(0, description="Number of alerts to skip"),
    db: Session = Depends(get_db)
):
    """
    Get security alerts for a tenant with optional filtering
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        query = db.query(SecurityAlert).filter(SecurityAlert.tenant_id == tenant_id)
        
        if status:
            query = query.filter(SecurityAlert.status == status)
        if severity:
            query = query.filter(SecurityAlert.severity == severity)
        
        alerts = query.order_by(SecurityAlert.created_at.desc()).offset(offset).limit(limit).all()
        
        return [
            AlertResponse(
                id=alert.id,
                alert_type=alert.alert_type,
                title=alert.title,
                description=alert.description,
                severity=alert.severity,
                confidence_score=alert.confidence_score,
                username=alert.username,
                source_ip=alert.source_ip,
                affected_systems=alert.affected_systems or [],
                status=alert.status,
                created_at=alert.created_at,
                correlation_data=alert.correlation_data
            )
            for alert in alerts
        ]
        
    except Exception as e:
        logger.error(f"Error retrieving security alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve alerts: {str(e)}")

@detection_router.put("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    status: str = Query(..., description="New status: open, investigating, resolved, false_positive"),
    resolution_notes: Optional[str] = Query(None, description="Resolution notes"),
    assigned_to: Optional[str] = Query(None, description="Assigned analyst"),
    tenant_id: str = Query(..., description="Tenant ID"),
    db: Session = Depends(get_db)
):
    """
    Update the status of a security alert
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        alert = db.query(SecurityAlert).filter(
            SecurityAlert.id == alert_id,
            SecurityAlert.tenant_id == tenant_id
        ).first()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        alert.status = status
        if resolution_notes:
            alert.resolution_notes = resolution_notes
        if assigned_to:
            alert.assigned_to = assigned_to
        if status in ['resolved', 'false_positive']:
            alert.resolved_at = datetime.utcnow()
        
        alert.updated_at = datetime.utcnow()
        db.commit()
        
        return {
            "status": "success",
            "message": f"Alert {alert_id} status updated to {status}"
        }
        
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update alert: {str(e)}")

# Behavioral baseline management endpoints
@detection_router.get("/baselines", response_model=List[BaselineResponse])
async def get_user_baselines(
    tenant_id: str = Query(..., description="Tenant ID"),
    username: Optional[str] = Query(None, description="Filter by username"),
    limit: int = Query(50, description="Maximum number of baselines to return"),
    offset: int = Query(0, description="Number of baselines to skip"),
    db: Session = Depends(get_db)
):
    """
    Get user behavior baselines for a tenant
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        query = db.query(UserBehaviorBaseline).filter(UserBehaviorBaseline.tenant_id == tenant_id)
        
        if username:
            query = query.filter(UserBehaviorBaseline.username == username)
        
        baselines = query.order_by(UserBehaviorBaseline.last_updated.desc()).offset(offset).limit(limit).all()
        
        return [
            BaselineResponse(
                id=baseline.id,
                username=baseline.username,
                typical_login_hours=baseline.typical_login_hours or [],
                typical_days=baseline.typical_days or [],
                avg_session_duration=baseline.avg_session_duration or 0.0,
                typical_countries=baseline.typical_countries or [],
                typical_ips=baseline.typical_ips or [],
                avg_daily_logins=baseline.avg_daily_logins or 0.0,
                confidence_score=baseline.confidence_score or 0.0,
                last_updated=baseline.last_updated
            )
            for baseline in baselines
        ]
        
    except Exception as e:
        logger.error(f"Error retrieving user baselines: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve baselines: {str(e)}")

@detection_router.post("/baselines/rebuild")
async def rebuild_user_baselines(
    tenant_id: str = Query(..., description="Tenant ID"),
    username: Optional[str] = Query(None, description="Specific username to rebuild (optional)"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    """
    Rebuild behavioral baselines for users
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        detection_engine = create_detection_engine()
        if not detection_engine:
            raise HTTPException(status_code=503, detail="Detection engine not available")
        
        # Add baseline rebuild task to background
        def rebuild_task():
            if username:
                # Rebuild specific user baseline
                from database import User
                user = db.query(User).filter(
                    User.tenant_id == tenant_id,
                    User.email == username
                ).first()
                if user:
                    detection_engine.behavioral_analyzer.build_user_baseline(
                        tenant_id, user.id, username
                    )
                    return 1
                return 0
            else:
                # Rebuild all baselines for tenant
                return detection_engine.update_user_baselines(tenant_id)
        
        background_tasks.add_task(rebuild_task)
        
        return {
            "status": "success",
            "message": f"Baseline rebuild initiated for {'user ' + username if username else 'all users'}"
        }
        
    except Exception as e:
        logger.error(f"Error initiating baseline rebuild: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate baseline rebuild: {str(e)}")

# Detection rule management endpoints
@detection_router.get("/rules", response_model=List[DetectionRuleResponse])
async def get_detection_rules(
    tenant_id: str = Query(..., description="Tenant ID"),
    rule_type: Optional[str] = Query(None, description="Filter by rule type"),
    is_enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    db: Session = Depends(get_db)
):
    """
    Get detection rules for a tenant
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        query = db.query(DetectionRule).filter(DetectionRule.tenant_id == tenant_id)
        
        if rule_type:
            query = query.filter(DetectionRule.rule_type == rule_type)
        if is_enabled is not None:
            query = query.filter(DetectionRule.is_enabled == is_enabled)
        
        rules = query.order_by(DetectionRule.created_at.desc()).all()
        
        return [
            DetectionRuleResponse(
                id=rule.id,
                rule_name=rule.rule_name,
                rule_type=rule.rule_type,
                description=rule.description,
                is_enabled=rule.is_enabled,
                severity=rule.severity,
                confidence_threshold=rule.confidence_threshold,
                parameters=rule.parameters or {},
                created_at=rule.created_at,
                updated_at=rule.updated_at
            )
            for rule in rules
        ]
        
    except Exception as e:
        logger.error(f"Error retrieving detection rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve rules: {str(e)}")

@detection_router.post("/rules", response_model=DetectionRuleResponse)
async def create_detection_rule(
    rule: DetectionRuleRequest,
    tenant_id: str = Query(..., description="Tenant ID"),
    created_by: str = Query(..., description="User creating the rule"),
    db: Session = Depends(get_db)
):
    """
    Create a new detection rule
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        new_rule = DetectionRule(
            tenant_id=tenant_id,
            rule_name=rule.rule_name,
            rule_type=rule.rule_type,
            description=rule.description,
            is_enabled=rule.is_enabled,
            severity=rule.severity,
            confidence_threshold=rule.confidence_threshold,
            parameters=rule.parameters,
            created_by=created_by
        )
        
        db.add(new_rule)
        db.commit()
        db.refresh(new_rule)
        
        return DetectionRuleResponse(
            id=new_rule.id,
            rule_name=new_rule.rule_name,
            rule_type=new_rule.rule_type,
            description=new_rule.description,
            is_enabled=new_rule.is_enabled,
            severity=new_rule.severity,
            confidence_threshold=new_rule.confidence_threshold,
            parameters=new_rule.parameters or {},
            created_at=new_rule.created_at,
            updated_at=new_rule.updated_at
        )
        
    except Exception as e:
        logger.error(f"Error creating detection rule: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create rule: {str(e)}")

@detection_router.post("/rules/initialize-defaults")
async def initialize_default_rules(
    tenant_id: str = Query(..., description="Tenant ID"),
    db: Session = Depends(get_db)
):
    """
    Initialize default detection rules for a tenant
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        # Check if rules already exist
        existing_rules = db.query(DetectionRule).filter(DetectionRule.tenant_id == tenant_id).count()
        
        if existing_rules > 0:
            return {
                "status": "info",
                "message": f"Tenant already has {existing_rules} detection rules"
            }
        
        # Initialize default rules
        rules = initialize_default_detection_rules(tenant_id, db)
        
        return {
            "status": "success",
            "message": f"Initialized {len(rules)} default detection rules",
            "rule_ids": [rule.id for rule in rules]
        }
        
    except Exception as e:
        logger.error(f"Error initializing default rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initialize rules: {str(e)}")

# Statistics and monitoring endpoints
@detection_router.get("/stats", response_model=DetectionStatsResponse)
async def get_detection_statistics(
    tenant_id: str = Query(..., description="Tenant ID"),
    db: Session = Depends(get_db)
):
    """
    Get detection system statistics for a tenant
    """
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        # Calculate 24-hour window
        cutoff_24h = datetime.utcnow() - timedelta(hours=24)
        
        # Total events in last 24 hours
        total_events_24h = db.query(AuthenticationEvent).filter(
            AuthenticationEvent.tenant_id == tenant_id,
            AuthenticationEvent.timestamp >= cutoff_24h
        ).count()
        
        # Total alerts in last 24 hours
        total_alerts_24h = db.query(SecurityAlert).filter(
            SecurityAlert.tenant_id == tenant_id,
            SecurityAlert.created_at >= cutoff_24h
        ).count()
        
        # Active alerts
        active_alerts = db.query(SecurityAlert).filter(
            SecurityAlert.tenant_id == tenant_id,
            SecurityAlert.status.in_(['open', 'investigating'])
        ).count()
        
        # Top source IPs (last 24 hours)
        from sqlalchemy import func
        top_ips = db.query(
            AuthenticationEvent.source_ip,
            func.count(AuthenticationEvent.id).label('event_count')
        ).filter(
            AuthenticationEvent.tenant_id == tenant_id,
            AuthenticationEvent.timestamp >= cutoff_24h
        ).group_by(AuthenticationEvent.source_ip).order_by(
            func.count(AuthenticationEvent.id).desc()
        ).limit(5).all()
        
        top_source_ips = [
            {"ip": ip, "event_count": count}
            for ip, count in top_ips
        ]
        
        # Alert severity breakdown
        severity_counts = db.query(
            SecurityAlert.severity,
            func.count(SecurityAlert.id).label('count')
        ).filter(
            SecurityAlert.tenant_id == tenant_id,
            SecurityAlert.created_at >= cutoff_24h
        ).group_by(SecurityAlert.severity).all()
        
        alert_severity_breakdown = {
            severity: count for severity, count in severity_counts
        }
        
        # Calculate detection accuracy (simplified)
        total_recent_alerts = total_alerts_24h
        false_positives = db.query(SecurityAlert).filter(
            SecurityAlert.tenant_id == tenant_id,
            SecurityAlert.created_at >= cutoff_24h,
            SecurityAlert.status == 'false_positive'
        ).count()
        
        detection_accuracy = (
            (total_recent_alerts - false_positives) / max(1, total_recent_alerts)
        ) if total_recent_alerts > 0 else 1.0
        
        return DetectionStatsResponse(
            total_events_24h=total_events_24h,
            total_alerts_24h=total_alerts_24h,
            active_alerts=active_alerts,
            top_source_ips=top_source_ips,
            alert_severity_breakdown=alert_severity_breakdown,
            detection_accuracy=detection_accuracy
        )
        
    except Exception as e:
        logger.error(f"Error retrieving detection statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve statistics: {str(e)}")

# Health check endpoint
@detection_router.get("/health")
async def detection_health_check():
    """
    Health check for the detection system
    """
    try:
        detection_engine = create_detection_engine()
        
        return {
            "status": "healthy" if detection_engine else "degraded",
            "database_available": DATABASE_AVAILABLE,
            "detection_engine_available": detection_engine is not None,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Detection health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

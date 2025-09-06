"""
BITS-SIEM False Positive Management API
======================================

This module provides REST API endpoints for managing false positive reduction
settings including whitelists, business hours, and behavioral profiles.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, time
import logging

from database import get_db, DATABASE_AVAILABLE
from sqlalchemy.orm import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create router
fp_router = APIRouter(prefix="/api/false-positive", tags=["false-positive"])

# Pydantic models for API requests/responses
class WhitelistEntryRequest(BaseModel):
    entry_type: str = Field(..., description="Type of whitelist entry (ip, network, user_agent, service_account)")
    value: str = Field(..., description="Value to whitelist")
    reason: str = Field(..., description="Reason for whitelisting")
    expires_at: Optional[datetime] = Field(None, description="Expiration time (optional)")
    confidence: float = Field(1.0, description="Confidence score (0.0-1.0)")

class WhitelistEntryResponse(BaseModel):
    id: str
    tenant_id: str
    entry_type: str
    value: str
    reason: str
    created_at: datetime
    expires_at: Optional[datetime]
    confidence: float
    auto_generated: bool

class BusinessHoursRequest(BaseModel):
    timezone: str = Field("UTC", description="Timezone for business hours")
    weekday_start: time = Field(..., description="Weekday start time")
    weekday_end: time = Field(..., description="Weekday end time")
    weekend_start: Optional[time] = Field(None, description="Weekend start time")
    weekend_end: Optional[time] = Field(None, description="Weekend end time")
    holidays: List[str] = Field([], description="List of holiday dates (ISO format)")

class MaintenanceWindowRequest(BaseModel):
    start_time: datetime = Field(..., description="Maintenance window start")
    end_time: datetime = Field(..., description="Maintenance window end")
    authorized_ips: List[str] = Field([], description="IPs authorized during maintenance")
    description: str = Field("", description="Description of maintenance")

class UserProfileResponse(BaseModel):
    user_identifier: str
    profile_type: str
    typical_hours: List[int]
    typical_days: List[int]
    failure_tolerance: int
    confidence_score: float
    sample_size: int
    last_updated: datetime

class FalsePositiveStatsResponse(BaseModel):
    total_alerts: int
    suppressed_alerts: int
    suppression_rate: float
    whitelist_suppressions: int
    behavioral_suppressions: int
    business_hours_suppressions: int
    top_suppression_reasons: List[Dict[str, Any]]

# Whitelist Management Endpoints
@fp_router.post("/whitelist", response_model=Dict[str, str])
async def add_whitelist_entry(
    entry: WhitelistEntryRequest,
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Add entry to static whitelist"""
    try:
        # Import here to avoid circular imports
        from processing.false_positive_reduction import fp_reduction_engine, WhitelistEntry
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        # Create whitelist entry
        whitelist_entry = WhitelistEntry(
            id=f"{entry.entry_type}_{entry.value}_{int(datetime.utcnow().timestamp())}",
            tenant_id=tenant_id,
            entry_type=entry.entry_type,
            value=entry.value,
            reason=entry.reason,
            created_at=datetime.utcnow(),
            expires_at=entry.expires_at,
            confidence=entry.confidence,
            auto_generated=False
        )
        
        # Add to whitelist asynchronously
        background_tasks.add_task(
            fp_reduction_engine.static_whitelist.add_whitelist_entry,
            whitelist_entry
        )
        
        logger.info(f"Added whitelist entry: {entry.entry_type}={entry.value} for tenant {tenant_id}")
        
        return {
            "status": "success",
            "message": f"Whitelist entry added: {entry.entry_type}={entry.value}",
            "entry_id": whitelist_entry.id
        }
        
    except Exception as e:
        logger.error(f"Error adding whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add whitelist entry: {str(e)}")

@fp_router.delete("/whitelist")
async def remove_whitelist_entry(
    entry_type: str = Query(..., description="Type of whitelist entry"),
    value: str = Query(..., description="Value to remove from whitelist"),
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Remove entry from static whitelist"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        # Remove from whitelist asynchronously
        background_tasks.add_task(
            fp_reduction_engine.static_whitelist.remove_whitelist_entry,
            tenant_id, entry_type, value
        )
        
        logger.info(f"Removed whitelist entry: {entry_type}={value} for tenant {tenant_id}")
        
        return {
            "status": "success",
            "message": f"Whitelist entry removed: {entry_type}={value}"
        }
        
    except Exception as e:
        logger.error(f"Error removing whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove whitelist entry: {str(e)}")

@fp_router.get("/whitelist/check")
async def check_whitelist(
    entry_type: str = Query(..., description="Type of entry to check"),
    value: str = Query(..., description="Value to check"),
    tenant_id: str = Query(..., description="Tenant ID")
):
    """Check if value is whitelisted"""
    try:
        # Try to import the false positive reduction engine
        try:
            import sys
            import os
            # Add processing directory to path
            processing_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'processing')
            if processing_path not in sys.path:
                sys.path.append(processing_path)
            
            from false_positive_reduction import fp_reduction_engine
        except ImportError as e:
            logger.error(f"Error importing false positive reduction: {e}")
            # Return a simple check for now
            return {
                "whitelisted": False,
                "reason": "False positive reduction engine not available",
                "confidence": 0.0,
                "source": "fallback"
            }
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        # Check static whitelist
        static_entry = await fp_reduction_engine.static_whitelist.is_whitelisted(
            tenant_id, entry_type, value
        )
        
        # Check dynamic whitelist for IPs
        dynamic_entry = None
        if entry_type == "ip":
            dynamic_entry = await fp_reduction_engine.dynamic_whitelist.is_dynamically_whitelisted(
                tenant_id, value
            )
        
        return {
            "is_whitelisted": static_entry is not None or dynamic_entry is not None,
            "static_whitelist": {
                "found": static_entry is not None,
                "reason": static_entry.reason if static_entry else None,
                "confidence": static_entry.confidence if static_entry else None
            },
            "dynamic_whitelist": {
                "found": dynamic_entry is not None,
                "success_count": dynamic_entry.get('success_count') if dynamic_entry else None,
                "confidence": dynamic_entry.get('confidence') if dynamic_entry else None
            }
        }
        
    except Exception as e:
        logger.error(f"Error checking whitelist: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check whitelist: {str(e)}")

# Business Hours Management
@fp_router.post("/business-hours")
async def set_business_hours(
    config: BusinessHoursRequest,
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Set business hours configuration for tenant"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine, BusinessHoursConfig
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        # Create business hours config
        business_config = BusinessHoursConfig(
            tenant_id=tenant_id,
            timezone=config.timezone,
            weekday_start=config.weekday_start,
            weekday_end=config.weekday_end,
            weekend_start=config.weekend_start,
            weekend_end=config.weekend_end,
            holidays=config.holidays
        )
        
        # Set configuration asynchronously
        background_tasks.add_task(
            fp_reduction_engine.business_hours.set_business_hours,
            business_config
        )
        
        logger.info(f"Set business hours for tenant {tenant_id}")
        
        return {
            "status": "success",
            "message": "Business hours configuration updated",
            "config": {
                "weekday_hours": f"{config.weekday_start} - {config.weekday_end}",
                "weekend_hours": f"{config.weekend_start} - {config.weekend_end}" if config.weekend_start else "None",
                "timezone": config.timezone,
                "holidays_count": len(config.holidays)
            }
        }
        
    except Exception as e:
        logger.error(f"Error setting business hours: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to set business hours: {str(e)}")

@fp_router.get("/business-hours/check")
async def check_business_hours(
    timestamp: datetime = Query(..., description="Timestamp to check"),
    tenant_id: str = Query(..., description="Tenant ID")
):
    """Check if timestamp is within business hours"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        is_business_hours = await fp_reduction_engine.business_hours.is_business_hours(
            tenant_id, timestamp
        )
        
        return {
            "timestamp": timestamp.isoformat(),
            "is_business_hours": is_business_hours,
            "day_of_week": timestamp.strftime("%A"),
            "time": timestamp.time().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error checking business hours: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check business hours: {str(e)}")

# Maintenance Windows
@fp_router.post("/maintenance-window")
async def add_maintenance_window(
    window: MaintenanceWindowRequest,
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Add maintenance window"""
    try:
        from processing.enhanced_detection import enhanced_detection_engine
        
        if not enhanced_detection_engine.enabled:
            raise HTTPException(status_code=503, detail="Enhanced detection not available")
        
        # Add maintenance window asynchronously
        background_tasks.add_task(
            enhanced_detection_engine.legitimate_detector.add_maintenance_window,
            tenant_id, window.start_time, window.end_time, window.authorized_ips, window.description
        )
        
        logger.info(f"Added maintenance window for tenant {tenant_id}: {window.start_time} - {window.end_time}")
        
        return {
            "status": "success",
            "message": "Maintenance window added",
            "window": {
                "start": window.start_time.isoformat(),
                "end": window.end_time.isoformat(),
                "duration_hours": (window.end_time - window.start_time).total_seconds() / 3600,
                "authorized_ips_count": len(window.authorized_ips)
            }
        }
        
    except Exception as e:
        logger.error(f"Error adding maintenance window: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add maintenance window: {str(e)}")

# User Behavior Profiles
@fp_router.get("/user-profile", response_model=UserProfileResponse)
async def get_user_profile(
    user_identifier: str = Query(..., description="User identifier"),
    tenant_id: str = Query(..., description="Tenant ID")
):
    """Get user behavioral profile"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        profile = await fp_reduction_engine.behavioral_analysis.get_user_profile(
            tenant_id, user_identifier
        )
        
        if not profile:
            raise HTTPException(status_code=404, detail="User profile not found")
        
        return UserProfileResponse(
            user_identifier=profile.user_identifier,
            profile_type=profile.profile_type,
            typical_hours=profile.typical_hours,
            typical_days=profile.typical_days,
            failure_tolerance=profile.failure_tolerance,
            confidence_score=profile.confidence_score,
            sample_size=profile.sample_size,
            last_updated=profile.last_updated
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user profile: {str(e)}")

@fp_router.post("/user-profile/rebuild")
async def rebuild_user_profile(
    user_identifier: str = Query(..., description="User identifier"),
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Rebuild user behavioral profile"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        # Rebuild profile asynchronously
        background_tasks.add_task(
            fp_reduction_engine.behavioral_analysis.build_user_profile,
            tenant_id, user_identifier
        )
        
        logger.info(f"Rebuilding user profile for {user_identifier} in tenant {tenant_id}")
        
        return {
            "status": "success",
            "message": f"User profile rebuild initiated for {user_identifier}"
        }
        
    except Exception as e:
        logger.error(f"Error rebuilding user profile: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to rebuild user profile: {str(e)}")

# Statistics and Monitoring
@fp_router.get("/stats", response_model=FalsePositiveStatsResponse)
async def get_false_positive_stats(
    tenant_id: str = Query(..., description="Tenant ID"),
    hours: int = Query(24, description="Hours to look back for statistics")
):
    """Get false positive reduction statistics"""
    try:
        # This would typically query the database for actual statistics
        # For now, return mock data
        return FalsePositiveStatsResponse(
            total_alerts=150,
            suppressed_alerts=45,
            suppression_rate=0.30,
            whitelist_suppressions=20,
            behavioral_suppressions=15,
            business_hours_suppressions=10,
            top_suppression_reasons=[
                {"reason": "Static IP whitelist", "count": 20},
                {"reason": "Dynamic IP whitelist", "count": 12},
                {"reason": "Service account behavior", "count": 8},
                {"reason": "Business hours context", "count": 5}
            ]
        )
        
    except Exception as e:
        logger.error(f"Error getting false positive stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

# Initialization and Management
@fp_router.post("/initialize")
async def initialize_false_positive_reduction(
    tenant_id: str = Query(..., description="Tenant ID"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Initialize default false positive reduction settings for tenant"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine
        
        if not fp_reduction_engine.enabled:
            raise HTTPException(status_code=503, detail="False positive reduction not available")
        
        # Initialize default whitelists asynchronously
        background_tasks.add_task(
            fp_reduction_engine.initialize_default_whitelists,
            tenant_id
        )
        
        logger.info(f"Initializing false positive reduction for tenant {tenant_id}")
        
        return {
            "status": "success",
            "message": f"False positive reduction initialized for tenant {tenant_id}",
            "initialized": [
                "Default internal network whitelists",
                "Common service user agents",
                "Basic business hours template"
            ]
        }
        
    except Exception as e:
        logger.error(f"Error initializing false positive reduction: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initialize: {str(e)}")

@fp_router.get("/health")
async def health_check():
    """Health check for false positive reduction system"""
    try:
        from processing.false_positive_reduction import fp_reduction_engine
        from processing.enhanced_detection import enhanced_detection_engine
        
        return {
            "status": "healthy",
            "components": {
                "false_positive_reduction": {
                    "enabled": fp_reduction_engine.enabled,
                    "redis_connected": fp_reduction_engine.redis_client is not None
                },
                "enhanced_detection": {
                    "enabled": enhanced_detection_engine.enabled,
                    "redis_connected": enhanced_detection_engine.redis_client is not None
                }
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

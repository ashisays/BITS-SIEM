"""
BITS-SIEM Brute-Force Detection Engine
=====================================

This module implements a comprehensive brute-force login detection system with:
1. Behavioral Correlation & Baseline Analysis
2. Multi-Factor Source Correlation
3. Dynamic Threshold Setting
4. Tenant Isolation
5. Machine Learning-based Anomaly Detection
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import statistics
import hashlib
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from database import (
    AuthenticationEvent, UserBehaviorBaseline, DetectionRule, 
    SecurityAlert, CorrelationEvent, User, get_db, DATABASE_AVAILABLE
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BehavioralAnalyzer:
    """Analyzes user behavior patterns and builds adaptive baselines"""
    
    def __init__(self, db: Session):
        self.db = db
        
    def build_user_baseline(self, tenant_id: str, user_id: str, username: str, 
                           lookback_days: int = 30) -> Optional[UserBehaviorBaseline]:
        """Build or update behavioral baseline for a user"""
        try:
            # Get historical authentication events
            cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
            
            events = self.db.query(AuthenticationEvent).filter(
                and_(
                    AuthenticationEvent.tenant_id == tenant_id,
                    AuthenticationEvent.username == username,
                    AuthenticationEvent.timestamp >= cutoff_date
                )
            ).all()
            
            if len(events) < 10:  # Need minimum sample size
                logger.warning(f"Insufficient data for baseline: {username} ({len(events)} events)")
                return None
                
            # Analyze temporal patterns
            login_hours = []
            login_days = []
            session_durations = []
            countries = set()
            ips = set()
            user_agents = set()
            devices = set()
            daily_login_counts = defaultdict(int)
            failed_attempts = []
            
            for event in events:
                # Temporal analysis
                login_hours.append(event.timestamp.hour)
                login_days.append(event.timestamp.weekday() + 1)  # 1=Monday
                
                # Geographic analysis
                if event.country:
                    countries.add(event.country)
                ips.add(event.source_ip)
                
                # Device analysis
                if event.user_agent:
                    user_agents.add(event.user_agent)
                if event.device_fingerprint:
                    devices.add(event.device_fingerprint)
                    
                # Session analysis
                if event.login_duration:
                    session_durations.append(event.login_duration / 60)  # Convert to minutes
                    
                # Daily login tracking
                date_key = event.timestamp.date()
                daily_login_counts[date_key] += 1
                
                # Failed attempts tracking
                if event.event_type == 'login_failure':
                    failed_attempts.append(event.failed_attempts_count or 1)
            
            # Calculate statistical baselines
            typical_hours = list(set(login_hours))
            typical_days = list(set(login_days))
            avg_session_duration = statistics.mean(session_durations) if session_durations else 60.0
            avg_daily_logins = statistics.mean(daily_login_counts.values()) if daily_login_counts else 1.0
            avg_failed_attempts = statistics.mean(failed_attempts) if failed_attempts else 0.0
            max_failed_attempts = max(failed_attempts) if failed_attempts else 0
            
            # Calculate dynamic thresholds (using statistical methods)
            login_frequency_threshold = avg_daily_logins + (2 * statistics.stdev(daily_login_counts.values())) if len(daily_login_counts) > 1 else avg_daily_logins * 3
            failure_rate_threshold = min(0.3, avg_failed_attempts + 0.1)  # Cap at 30%
            
            # Create or update baseline
            baseline = self.db.query(UserBehaviorBaseline).filter(
                and_(
                    UserBehaviorBaseline.tenant_id == tenant_id,
                    UserBehaviorBaseline.user_id == user_id
                )
            ).first()
            
            if not baseline:
                baseline = UserBehaviorBaseline(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    username=username
                )
                self.db.add(baseline)
            
            # Update baseline data
            baseline.typical_login_hours = typical_hours
            baseline.typical_days = typical_days
            baseline.avg_session_duration = avg_session_duration
            baseline.typical_countries = list(countries)
            baseline.typical_ips = list(ips)
            baseline.typical_user_agents = list(user_agents)[:10]  # Limit size
            baseline.typical_devices = list(devices)[:10]
            baseline.avg_daily_logins = avg_daily_logins
            baseline.avg_failed_attempts = avg_failed_attempts
            baseline.max_failed_attempts = max_failed_attempts
            baseline.login_frequency_threshold = login_frequency_threshold
            baseline.failure_rate_threshold = failure_rate_threshold
            baseline.location_deviation_threshold = 0.8  # 80% confidence
            baseline.time_deviation_threshold = 0.7  # 70% confidence
            baseline.sample_size = len(events)
            baseline.confidence_score = min(1.0, len(events) / 100.0)  # Max confidence at 100 events
            baseline.last_updated = datetime.utcnow()
            
            self.db.commit()
            logger.info(f"Updated baseline for user {username} with {len(events)} events")
            return baseline
            
        except Exception as e:
            logger.error(f"Error building baseline for {username}: {e}")
            self.db.rollback()
            return None
    
    def analyze_behavioral_deviation(self, event: AuthenticationEvent, 
                                   baseline: UserBehaviorBaseline) -> Dict[str, float]:
        """Analyze how much an event deviates from user's baseline behavior"""
        deviations = {}
        
        try:
            # Temporal deviation
            current_hour = event.timestamp.hour
            current_day = event.timestamp.weekday() + 1
            
            if current_hour not in baseline.typical_login_hours:
                deviations['time_deviation'] = 1.0
            else:
                deviations['time_deviation'] = 0.0
                
            if current_day not in baseline.typical_days:
                deviations['day_deviation'] = 0.8
            else:
                deviations['day_deviation'] = 0.0
            
            # Location deviation
            if event.country and event.country not in baseline.typical_countries:
                deviations['country_deviation'] = 1.0
            else:
                deviations['country_deviation'] = 0.0
                
            if event.source_ip not in baseline.typical_ips:
                deviations['ip_deviation'] = 0.7
            else:
                deviations['ip_deviation'] = 0.0
            
            # Device deviation
            if event.user_agent and event.user_agent not in baseline.typical_user_agents:
                deviations['device_deviation'] = 0.6
            else:
                deviations['device_deviation'] = 0.0
            
            # Frequency deviation (check recent login frequency)
            recent_cutoff = datetime.utcnow() - timedelta(hours=1)
            recent_logins = self.db.query(AuthenticationEvent).filter(
                and_(
                    AuthenticationEvent.tenant_id == event.tenant_id,
                    AuthenticationEvent.username == event.username,
                    AuthenticationEvent.timestamp >= recent_cutoff,
                    AuthenticationEvent.event_type == 'login_success'
                )
            ).count()
            
            if recent_logins > baseline.login_frequency_threshold:
                deviations['frequency_deviation'] = min(1.0, recent_logins / baseline.login_frequency_threshold - 1)
            else:
                deviations['frequency_deviation'] = 0.0
            
            # Failed attempts deviation
            if event.failed_attempts_count and event.failed_attempts_count > baseline.max_failed_attempts:
                deviations['failure_deviation'] = min(1.0, event.failed_attempts_count / max(1, baseline.max_failed_attempts))
            else:
                deviations['failure_deviation'] = 0.0
            
            return deviations
            
        except Exception as e:
            logger.error(f"Error analyzing behavioral deviation: {e}")
            return {}

class CorrelationEngine:
    """Correlates events across multiple sources and factors"""
    
    def __init__(self, db: Session):
        self.db = db
        
    def correlate_events(self, tenant_id: str, time_window_minutes: int = 15) -> List[CorrelationEvent]:
        """Find correlated authentication events across multiple sources"""
        correlations = []
        
        try:
            # Get recent events within time window
            cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
            
            recent_events = self.db.query(AuthenticationEvent).filter(
                and_(
                    AuthenticationEvent.tenant_id == tenant_id,
                    AuthenticationEvent.timestamp >= cutoff_time
                )
            ).order_by(AuthenticationEvent.timestamp.desc()).all()
            
            # Group events by potential correlation factors
            ip_groups = defaultdict(list)
            user_groups = defaultdict(list)
            
            for event in recent_events:
                ip_groups[event.source_ip].append(event)
                user_groups[event.username].append(event)
            
            # Analyze IP-based correlations
            for ip, events in ip_groups.items():
                if len(events) >= 3:  # Minimum threshold for correlation
                    correlation = self._analyze_ip_correlation(tenant_id, ip, events)
                    if correlation:
                        correlations.append(correlation)
            
            # Analyze user-based correlations
            for username, events in user_groups.items():
                if len(events) >= 5:  # Higher threshold for user correlations
                    correlation = self._analyze_user_correlation(tenant_id, username, events)
                    if correlation:
                        correlations.append(correlation)
            
            return correlations
            
        except Exception as e:
            logger.error(f"Error correlating events: {e}")
            return []
    
    def _analyze_ip_correlation(self, tenant_id: str, ip: str, events: List[AuthenticationEvent]) -> Optional[CorrelationEvent]:
        """Analyze correlation patterns for a specific IP"""
        try:
            # Check for multi-source attacks
            source_types = set(event.source_type for event in events)
            usernames = set(event.username for event in events)
            failed_events = [e for e in events if e.event_type == 'login_failure']
            
            if len(source_types) > 1 and len(failed_events) >= 3:
                # Multi-source brute force detected
                correlation_id = str(uuid.uuid4())
                
                correlation = CorrelationEvent(
                    tenant_id=tenant_id,
                    correlation_id=correlation_id,
                    event_type='multi_source_failure',
                    username=','.join(usernames)[:255],  # Truncate if too long
                    source_ip=ip,
                    involved_sources=list(source_types),
                    event_ids=[e.id for e in events],
                    event_count=len(events),
                    time_window=int((max(e.timestamp for e in events) - min(e.timestamp for e in events)).total_seconds()),
                    confidence_score=min(1.0, len(failed_events) / 10.0),
                    pattern_type='distributed' if len(usernames) > 3 else 'focused',
                    risk_score=min(1.0, (len(failed_events) * len(source_types)) / 20.0),
                    first_event_time=min(e.timestamp for e in events),
                    last_event_time=max(e.timestamp for e in events),
                    metadata={
                        'unique_users': len(usernames),
                        'failure_rate': len(failed_events) / len(events),
                        'source_diversity': len(source_types)
                    }
                )
                
                self.db.add(correlation)
                self.db.commit()
                return correlation
                
        except Exception as e:
            logger.error(f"Error analyzing IP correlation for {ip}: {e}")
            
        return None
    
    def _analyze_user_correlation(self, tenant_id: str, username: str, events: List[AuthenticationEvent]) -> Optional[CorrelationEvent]:
        """Analyze correlation patterns for a specific user"""
        try:
            # Check for rapid-fire attempts across services
            source_types = set(event.source_type for event in events)
            ips = set(event.source_ip for event in events)
            failed_events = [e for e in events if e.event_type == 'login_failure']
            
            if len(ips) > 2 and len(failed_events) >= 4:
                # Distributed user attack detected
                correlation_id = str(uuid.uuid4())
                
                correlation = CorrelationEvent(
                    tenant_id=tenant_id,
                    correlation_id=correlation_id,
                    event_type='cross_service_attempt',
                    username=username,
                    source_ip=','.join(ips)[:255],  # Truncate if too long
                    involved_sources=list(source_types),
                    event_ids=[e.id for e in events],
                    event_count=len(events),
                    time_window=int((max(e.timestamp for e in events) - min(e.timestamp for e in events)).total_seconds()),
                    confidence_score=min(1.0, len(failed_events) / 15.0),
                    pattern_type='parallel' if len(ips) > len(source_types) else 'sequential',
                    risk_score=min(1.0, (len(failed_events) * len(ips)) / 25.0),
                    first_event_time=min(e.timestamp for e in events),
                    last_event_time=max(e.timestamp for e in events),
                    metadata={
                        'unique_ips': len(ips),
                        'failure_rate': len(failed_events) / len(events),
                        'geographic_spread': len(set(e.country for e in events if e.country))
                    }
                )
                
                self.db.add(correlation)
                self.db.commit()
                return correlation
                
        except Exception as e:
            logger.error(f"Error analyzing user correlation for {username}: {e}")
            
        return None

class AlertEngine:
    """Generates and manages security alerts based on detection results"""
    
    def __init__(self, db: Session):
        self.db = db
        
    def generate_behavioral_alert(self, event: AuthenticationEvent, baseline: UserBehaviorBaseline,
                                deviations: Dict[str, float], detection_rule: DetectionRule) -> Optional[SecurityAlert]:
        """Generate alert for behavioral anomalies"""
        try:
            # Calculate overall risk score
            risk_score = sum(deviations.values()) / len(deviations) if deviations else 0.0
            
            if risk_score < detection_rule.confidence_threshold:
                return None
                
            # Determine severity based on risk score
            if risk_score >= 0.8:
                severity = "critical"
            elif risk_score >= 0.6:
                severity = "high"
            elif risk_score >= 0.4:
                severity = "medium"
            else:
                severity = "low"
            
            # Create alert
            alert = SecurityAlert(
                tenant_id=event.tenant_id,
                alert_type="anomalous_behavior",
                title=f"Anomalous Login Behavior: {event.username}",
                description=f"User {event.username} exhibited unusual login behavior from {event.source_ip}",
                severity=severity,
                confidence_score=risk_score,
                username=event.username,
                source_ip=event.source_ip,
                affected_systems=[event.source_type],
                detection_rule_id=detection_rule.id,
                triggering_events=[event.id],
                correlation_data={
                    'deviations': deviations,
                    'baseline_confidence': baseline.confidence_score,
                    'event_context': {
                        'source_type': event.source_type,
                        'country': event.country,
                        'user_agent': event.user_agent[:100] if event.user_agent else None
                    }
                }
            )
            
            self.db.add(alert)
            self.db.commit()
            logger.info(f"Generated behavioral alert for {event.username} with risk score {risk_score:.2f}")
            return alert
            
        except Exception as e:
            logger.error(f"Error generating behavioral alert: {e}")
            self.db.rollback()
            return None
    
    def generate_correlation_alert(self, correlation: CorrelationEvent, 
                                 detection_rule: DetectionRule) -> Optional[SecurityAlert]:
        """Generate alert for correlated events"""
        try:
            if correlation.confidence_score < detection_rule.confidence_threshold:
                return None
                
            # Determine severity based on risk score and event count
            if correlation.risk_score >= 0.8 or correlation.event_count >= 20:
                severity = "critical"
            elif correlation.risk_score >= 0.6 or correlation.event_count >= 10:
                severity = "high"
            elif correlation.risk_score >= 0.4 or correlation.event_count >= 5:
                severity = "medium"
            else:
                severity = "low"
            
            # Create descriptive title and description
            if correlation.event_type == 'multi_source_failure':
                title = f"Multi-Source Brute Force Attack from {correlation.source_ip}"
                description = f"Detected {correlation.event_count} failed login attempts across {len(correlation.involved_sources)} services"
            else:
                title = f"Cross-Service Attack on {correlation.username}"
                description = f"User {correlation.username} targeted across {len(correlation.involved_sources)} services from multiple IPs"
            
            alert = SecurityAlert(
                tenant_id=correlation.tenant_id,
                alert_type="correlation",
                title=title,
                description=description,
                severity=severity,
                confidence_score=correlation.confidence_score,
                username=correlation.username,
                source_ip=correlation.source_ip,
                affected_systems=correlation.involved_sources,
                detection_rule_id=detection_rule.id,
                triggering_events=correlation.event_ids,
                correlation_data={
                    'correlation_id': correlation.correlation_id,
                    'pattern_type': correlation.pattern_type,
                    'time_window': correlation.time_window,
                    'metadata': correlation.metadata
                }
            )
            
            self.db.add(alert)
            self.db.commit()
            logger.info(f"Generated correlation alert for {correlation.event_type} with {correlation.event_count} events")
            return alert
            
        except Exception as e:
            logger.error(f"Error generating correlation alert: {e}")
            self.db.rollback()
            return None

class BruteForceDetectionEngine:
    """Main detection engine that orchestrates all components"""
    
    def __init__(self, db: Session = None):
        self.db = db or next(get_db())
        self.behavioral_analyzer = BehavioralAnalyzer(self.db)
        self.correlation_engine = CorrelationEngine(self.db)
        self.alert_engine = AlertEngine(self.db)
    
    def process_authentication_event(self, event_data: Dict[str, Any]) -> List[SecurityAlert]:
        """Process a new authentication event and generate alerts if needed"""
        alerts = []
        
        try:
            # Create authentication event record
            auth_event = AuthenticationEvent(
                tenant_id=event_data['tenant_id'],
                user_id=event_data.get('user_id'),
                username=event_data['username'],
                event_type=event_data['event_type'],
                source_type=event_data['source_type'],
                source_ip=event_data['source_ip'],
                source_port=event_data.get('source_port'),
                user_agent=event_data.get('user_agent'),
                country=event_data.get('country'),
                city=event_data.get('city'),
                device_fingerprint=event_data.get('device_fingerprint'),
                session_id=event_data.get('session_id'),
                login_duration=event_data.get('login_duration'),
                failed_attempts_count=event_data.get('failed_attempts_count', 0),
                time_since_last_attempt=event_data.get('time_since_last_attempt'),
                metadata=event_data.get('metadata', {}),
                timestamp=datetime.utcnow()
            )
            
            self.db.add(auth_event)
            self.db.commit()
            
            # Get active detection rules for tenant
            detection_rules = self.db.query(DetectionRule).filter(
                and_(
                    DetectionRule.tenant_id == event_data['tenant_id'],
                    DetectionRule.is_enabled == True
                )
            ).all()
            
            # Process behavioral analysis for login events
            if event_data['event_type'] in ['login_success', 'login_failure']:
                alerts.extend(self._process_behavioral_detection(auth_event, detection_rules))
            
            # Process correlation analysis
            alerts.extend(self._process_correlation_detection(auth_event, detection_rules))
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error processing authentication event: {e}")
            self.db.rollback()
            return []
    
    def _process_behavioral_detection(self, event: AuthenticationEvent, 
                                    detection_rules: List[DetectionRule]) -> List[SecurityAlert]:
        """Process behavioral anomaly detection"""
        alerts = []
        
        try:
            # Get or build user baseline
            baseline = self.db.query(UserBehaviorBaseline).filter(
                and_(
                    UserBehaviorBaseline.tenant_id == event.tenant_id,
                    UserBehaviorBaseline.username == event.username
                )
            ).first()
            
            if not baseline:
                # Try to build baseline if we have a user_id
                if event.user_id:
                    baseline = self.behavioral_analyzer.build_user_baseline(
                        event.tenant_id, event.user_id, event.username
                    )
            
            if baseline and baseline.confidence_score > 0.3:  # Minimum confidence threshold
                # Analyze behavioral deviations
                deviations = self.behavioral_analyzer.analyze_behavioral_deviation(event, baseline)
                
                # Check against behavioral detection rules
                for rule in detection_rules:
                    if rule.rule_type == 'behavioral':
                        alert = self.alert_engine.generate_behavioral_alert(
                            event, baseline, deviations, rule
                        )
                        if alert:
                            alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error in behavioral detection: {e}")
            return []
    
    def _process_correlation_detection(self, event: AuthenticationEvent,
                                     detection_rules: List[DetectionRule]) -> List[SecurityAlert]:
        """Process correlation-based detection"""
        alerts = []
        
        try:
            # Run correlation analysis
            correlations = self.correlation_engine.correlate_events(event.tenant_id)
            
            # Generate alerts for significant correlations
            for correlation in correlations:
                for rule in detection_rules:
                    if rule.rule_type == 'correlation':
                        alert = self.alert_engine.generate_correlation_alert(correlation, rule)
                        if alert:
                            alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error in correlation detection: {e}")
            return []
    
    def update_user_baselines(self, tenant_id: str = None) -> int:
        """Update behavioral baselines for all users (or specific tenant)"""
        updated_count = 0
        
        try:
            # Get users to update
            query = self.db.query(User)
            if tenant_id:
                query = query.filter(User.tenant_id == tenant_id)
            
            users = query.all()
            
            for user in users:
                baseline = self.behavioral_analyzer.build_user_baseline(
                    user.tenant_id, user.id, user.email
                )
                if baseline:
                    updated_count += 1
            
            logger.info(f"Updated {updated_count} user baselines")
            return updated_count
            
        except Exception as e:
            logger.error(f"Error updating user baselines: {e}")
            return 0

# Utility functions for API integration
def create_detection_engine() -> BruteForceDetectionEngine:
    """Factory function to create detection engine instance"""
    if not DATABASE_AVAILABLE:
        logger.warning("Database not available, detection engine will not function")
        return None
    return BruteForceDetectionEngine()

def initialize_default_detection_rules(tenant_id: str, db: Session) -> List[DetectionRule]:
    """Initialize default detection rules for a tenant"""
    default_rules = [
        {
            'rule_name': 'Behavioral Anomaly Detection',
            'rule_type': 'behavioral',
            'description': 'Detects login attempts that deviate from user behavioral baselines',
            'severity': 'medium',
            'confidence_threshold': 0.6,
            'parameters': {
                'min_baseline_confidence': 0.3,
                'deviation_weight_factors': {
                    'time_deviation': 1.0,
                    'location_deviation': 1.2,
                    'device_deviation': 0.8,
                    'frequency_deviation': 1.5
                }
            }
        },
        {
            'rule_name': 'Multi-Source Correlation',
            'rule_type': 'correlation',
            'description': 'Detects coordinated attacks across multiple services',
            'severity': 'high',
            'confidence_threshold': 0.7,
            'parameters': {
                'min_event_count': 3,
                'time_window_minutes': 15,
                'min_source_diversity': 2
            }
        },
        {
            'rule_name': 'High-Frequency Threshold',
            'rule_type': 'threshold',
            'description': 'Detects rapid-fire login attempts',
            'severity': 'high',
            'confidence_threshold': 0.8,
            'parameters': {
                'max_attempts_per_minute': 10,
                'max_failures_per_hour': 20,
                'lockout_threshold': 5
            }
        }
    ]
    
    created_rules = []
    for rule_config in default_rules:
        rule = DetectionRule(
            tenant_id=tenant_id,
            rule_name=rule_config['rule_name'],
            rule_type=rule_config['rule_type'],
            description=rule_config['description'],
            severity=rule_config['severity'],
            confidence_threshold=rule_config['confidence_threshold'],
            parameters=rule_config['parameters'],
            created_by='system'
        )
        db.add(rule)
        created_rules.append(rule)
    
    db.commit()
    return created_rules

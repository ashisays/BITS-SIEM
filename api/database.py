from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey, Float, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from datetime import datetime, timedelta
import os

# Database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://siem:siempassword@db:5432/siemdb")

print(f"Connecting to database: {DATABASE_URL.replace('siempassword', '***')}")

# Create engine with connection pooling and retry logic
try:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        echo=False  # Set to True for SQL debugging
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    print("Database engine created successfully")
    DATABASE_AVAILABLE = True
except Exception as e:
    print(f"Failed to create database engine: {e}")
    DATABASE_AVAILABLE = False
    engine = None
    SessionLocal = None
    Base = None

# Database Models
if DATABASE_AVAILABLE and Base is not None:
    class Tenant(Base):
        __tablename__ = "tenants"
        
        id = Column(String, primary_key=True, index=True)
        name = Column(String, nullable=False)
        description = Column(Text)
        user_count = Column(Integer, default=0)
        sources_count = Column(Integer, default=0)
        status = Column(String, default="active")
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        users = relationship("User", back_populates="tenant")
        sources = relationship("Source", back_populates="tenant")
        notifications = relationship("Notification", back_populates="tenant")
        reports = relationship("Report", back_populates="tenant")
        auth_events = relationship("AuthenticationEvent", back_populates="tenant")
        user_baselines = relationship("UserBehaviorBaseline", back_populates="tenant")
        detection_rules = relationship("DetectionRule", back_populates="tenant")
        security_alerts = relationship("SecurityAlert", back_populates="tenant")
        correlation_events = relationship("CorrelationEvent", back_populates="tenant")

    class User(Base):
        __tablename__ = "users"
        
        id = Column(String, primary_key=True, index=True)
        email = Column(String, unique=True, index=True, nullable=False)
        name = Column(String, nullable=False)
        password = Column(String, nullable=False)  # In production, use hashed passwords
        role = Column(String, nullable=False, default="user")
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        tenants_access = Column(JSON)  # Additional tenants user can access
        is_active = Column(Boolean, default=True)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="users")

    class Source(Base):
        __tablename__ = "sources"
        
        id = Column(Integer, primary_key=True, index=True)
        name = Column(String, nullable=False)
        type = Column(String, nullable=False)
        ip = Column(String, nullable=False)
        port = Column(Integer, nullable=False)
        protocol = Column(String, nullable=False)
        status = Column(String, default="active")
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        notifications = Column(JSON)  # Notification settings
        last_activity = Column(DateTime, default=datetime.utcnow)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="sources")

    class Notification(Base):
        __tablename__ = "notifications"
        
        id = Column(Integer, primary_key=True, index=True)
        message = Column(Text, nullable=False)
        severity = Column(String, nullable=False, default="info")
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        is_read = Column(Boolean, default=False)
        meta_data = Column(JSON)
        created_at = Column(DateTime, default=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="notifications")

    class Report(Base):
        __tablename__ = "reports"
        
        id = Column(Integer, primary_key=True, index=True)
        title = Column(String, nullable=False)
        summary = Column(Text)
        report_type = Column(String, nullable=False)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        generated_by = Column(String, nullable=False)
        data = Column(JSON)
        created_at = Column(DateTime, default=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="reports")

    class AuthenticationEvent(Base):
        """Stores all authentication attempts with detailed context"""
        __tablename__ = "authentication_events"
        
        id = Column(Integer, primary_key=True, index=True)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        user_id = Column(String, ForeignKey("users.id"), nullable=True)  # Null for failed attempts with invalid users
        username = Column(String, nullable=False, index=True)
        
        # Event details
        event_type = Column(String, nullable=False)  # login_success, login_failure, logout
        source_type = Column(String, nullable=False)  # web, ssh, rdp, vpn, api, etc.
        source_ip = Column(String, nullable=False, index=True)
        source_port = Column(Integer)
        user_agent = Column(Text)
        
        # Geographic and device context
        country = Column(String)
        city = Column(String)
        device_fingerprint = Column(String)
        session_id = Column(String)
        
        # Behavioral context
        login_duration = Column(Integer)  # seconds
        failed_attempts_count = Column(Integer, default=0)
        time_since_last_attempt = Column(Integer)  # seconds
        
        # Metadata
        metadata = Column(JSON)
        timestamp = Column(DateTime, default=datetime.utcnow, index=True)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="auth_events")
        user = relationship("User")
        
        # Indexes for performance
        __table_args__ = (
            Index('idx_auth_tenant_user_time', 'tenant_id', 'username', 'timestamp'),
            Index('idx_auth_ip_time', 'source_ip', 'timestamp'),
            Index('idx_auth_type_time', 'event_type', 'timestamp'),
        )

    class UserBehaviorBaseline(Base):
        """Stores behavioral baselines for each user per tenant"""
        __tablename__ = "user_behavior_baselines"
        
        id = Column(Integer, primary_key=True, index=True)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        user_id = Column(String, ForeignKey("users.id"), nullable=False)
        username = Column(String, nullable=False, index=True)
        
        # Temporal patterns
        typical_login_hours = Column(JSON)  # [9, 10, 11, ..., 17] for 9AM-5PM
        typical_days = Column(JSON)  # [1, 2, 3, 4, 5] for weekdays
        avg_session_duration = Column(Float)  # minutes
        
        # Location patterns
        typical_countries = Column(JSON)  # ["US", "CA"]
        typical_ips = Column(JSON)  # ["192.168.1.100", "10.0.0.50"]
        
        # Device patterns
        typical_user_agents = Column(JSON)
        typical_devices = Column(JSON)
        
        # Behavioral metrics
        avg_daily_logins = Column(Float)
        avg_failed_attempts = Column(Float)
        max_failed_attempts = Column(Integer)
        
        # Statistical thresholds (dynamically calculated)
        login_frequency_threshold = Column(Float)  # logins per hour
        failure_rate_threshold = Column(Float)  # percentage
        location_deviation_threshold = Column(Float)
        time_deviation_threshold = Column(Float)
        
        # Baseline metadata
        sample_size = Column(Integer)  # number of events used for baseline
        confidence_score = Column(Float)  # 0.0 to 1.0
        last_updated = Column(DateTime, default=datetime.utcnow)
        created_at = Column(DateTime, default=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="user_baselines")
        user = relationship("User")
        
        # Unique constraint
        __table_args__ = (
            Index('idx_baseline_tenant_user', 'tenant_id', 'user_id', unique=True),
        )

    class DetectionRule(Base):
        """Configurable detection rules per tenant"""
        __tablename__ = "detection_rules"
        
        id = Column(Integer, primary_key=True, index=True)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        
        rule_name = Column(String, nullable=False)
        rule_type = Column(String, nullable=False)  # behavioral, correlation, threshold
        description = Column(Text)
        
        # Rule configuration
        is_enabled = Column(Boolean, default=True)
        severity = Column(String, default="medium")  # low, medium, high, critical
        confidence_threshold = Column(Float, default=0.7)  # 0.0 to 1.0
        
        # Rule parameters (JSON for flexibility)
        parameters = Column(JSON)  # Rule-specific configuration
        
        # Metadata
        created_by = Column(String, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="detection_rules")

    class SecurityAlert(Base):
        """Generated security alerts from detection system"""
        __tablename__ = "security_alerts"
        
        id = Column(Integer, primary_key=True, index=True)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        
        # Alert details
        alert_type = Column(String, nullable=False)  # brute_force, anomalous_behavior, correlation
        title = Column(String, nullable=False)
        description = Column(Text)
        severity = Column(String, nullable=False)  # low, medium, high, critical
        confidence_score = Column(Float, nullable=False)  # 0.0 to 1.0
        
        # Related entities
        username = Column(String, index=True)
        source_ip = Column(String, index=True)
        affected_systems = Column(JSON)  # List of affected sources/systems
        
        # Detection context
        detection_rule_id = Column(Integer, ForeignKey("detection_rules.id"))
        triggering_events = Column(JSON)  # IDs of events that triggered this alert
        correlation_data = Column(JSON)  # Cross-source correlation information
        
        # Alert lifecycle
        status = Column(String, default="open")  # open, investigating, resolved, false_positive
        assigned_to = Column(String)
        resolution_notes = Column(Text)
        resolved_at = Column(DateTime)
        
        # Metadata
        created_at = Column(DateTime, default=datetime.utcnow, index=True)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="security_alerts")
        detection_rule = relationship("DetectionRule")
        
        # Indexes for performance
        __table_args__ = (
            Index('idx_alert_tenant_status_time', 'tenant_id', 'status', 'created_at'),
            Index('idx_alert_severity_time', 'severity', 'created_at'),
        )

    class CorrelationEvent(Base):
        """Stores correlated events across multiple sources"""
        __tablename__ = "correlation_events"
        
        id = Column(Integer, primary_key=True, index=True)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
        
        # Correlation details
        correlation_id = Column(String, nullable=False, index=True)  # Groups related events
        event_type = Column(String, nullable=False)  # multi_source_failure, cross_service_attempt
        
        # Correlated data
        username = Column(String, index=True)
        source_ip = Column(String, index=True)
        involved_sources = Column(JSON)  # List of source types involved
        event_ids = Column(JSON)  # List of authentication_event IDs
        
        # Correlation metrics
        event_count = Column(Integer, nullable=False)
        time_window = Column(Integer)  # seconds between first and last event
        confidence_score = Column(Float)  # 0.0 to 1.0
        
        # Analysis results
        pattern_type = Column(String)  # sequential, parallel, distributed
        risk_score = Column(Float)  # 0.0 to 1.0
        metadata = Column(JSON)
        
        # Timestamps
        first_event_time = Column(DateTime, nullable=False)
        last_event_time = Column(DateTime, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="correlation_events")
        
        # Indexes for performance
        __table_args__ = (
            Index('idx_correlation_tenant_id', 'tenant_id', 'correlation_id'),
            Index('idx_correlation_ip_time', 'source_ip', 'first_event_time'),
        )

# Database session dependency
def get_db():
    if not DATABASE_AVAILABLE or SessionLocal is None:
        return None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database with sample data
def init_db():
    if not DATABASE_AVAILABLE or engine is None:
        print("Database not available - skipping initialization")
        return False
    
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully")
        
        # Create session
        db = SessionLocal()
        
        # Check if data already exists
        existing_tenants = db.query(Tenant).count()
        sre_user_exists = db.query(User).filter(User.email == "sre@bits.com").first()
        
        if existing_tenants > 0 and sre_user_exists:
            print("Database already initialized with sample data including SRE user")
            db.close()
            return True
        elif existing_tenants > 0 and not sre_user_exists:
            print("Database exists but SRE user missing - adding SRE user...")
        else:
            print("Initializing database with sample data...")
        
        # Create tenants (only if they don't exist)
        tenants_data = [
            {"id": "acme-corp", "name": "Acme Corporation", "description": "Technology company"},
            {"id": "beta-industries", "name": "Beta Industries", "description": "Manufacturing company"},
            {"id": "cisco-systems", "name": "Cisco Systems", "description": "Networking and cybersecurity company"},
            {"id": "demo-org", "name": "Demo Organization", "description": "Demo organization for testing"},
            {"id": "bits-internal", "name": "BITS Internal", "description": "Internal BITS organization for SRE team"}
        ]
        
        for tenant_data in tenants_data:
            existing_tenant = db.query(Tenant).filter(Tenant.id == tenant_data["id"]).first()
            if not existing_tenant:
                tenant = Tenant(**tenant_data)
                db.add(tenant)
                print(f"Created tenant: {tenant_data['name']}")
        
        # Create users (only if they don't exist)
        users_data = [
            {"id": "admin@acme.com", "email": "admin@acme.com", "password": "admin123", "name": "Acme Admin", "tenant_id": "acme-corp", "role": "admin", "tenants_access": ["acme-corp"]},
            {"id": "user@acme.com", "email": "user@acme.com", "password": "user123", "name": "Acme User", "tenant_id": "acme-corp", "role": "user", "tenants_access": ["acme-corp"]},
            {"id": "admin@beta.com", "email": "admin@beta.com", "password": "admin123", "name": "Beta Admin", "tenant_id": "beta-industries", "role": "admin", "tenants_access": ["beta-industries"]},
            {"id": "aspundir@cisco.com", "email": "aspundir@cisco.com", "password": "password123", "name": "Aspundir Singh", "tenant_id": "cisco-systems", "role": "admin", "tenants_access": ["cisco-systems"]},
            {"id": "admin@demo.com", "email": "admin@demo.com", "password": "demo123", "name": "Demo Admin", "tenant_id": "demo-org", "role": "admin", "tenants_access": ["demo-org"]},
            {"id": "user@demo.com", "email": "user@demo.com", "password": "demo123", "name": "Demo User", "tenant_id": "demo-org", "role": "user", "tenants_access": ["demo-org"]},
            {"id": "sre@bits.com", "email": "sre@bits.com", "password": "sre123", "name": "BITS SRE", "tenant_id": "bits-internal", "role": "sre", "tenants_access": ["bits-internal", "acme-corp", "beta-industries", "cisco-systems", "demo-org"]}
        ]
        
        for user_data in users_data:
            existing_user = db.query(User).filter(User.email == user_data["email"]).first()
            if not existing_user:
                user = User(**user_data)
                db.add(user)
                print(f"Created user: {user_data['name']} ({user_data['email']})")
        
        # Create sources
        sources_data = [
            {"name": "Web Server", "type": "web-server", "ip": "192.168.1.100", "port": 80, "protocol": "http", "tenant_id": "acme-corp", "notifications": {"enabled": True, "emails": ["admin@acme.com", "security@acme.com"]}},
            {"name": "Database Server", "type": "database", "ip": "192.168.1.200", "port": 3306, "protocol": "tcp", "tenant_id": "acme-corp", "notifications": {"enabled": True, "emails": ["dba@acme.com"]}},
            {"name": "Firewall", "type": "firewall", "ip": "10.0.1.1", "port": 514, "protocol": "udp", "status": "warning", "tenant_id": "beta-industries", "notifications": {"enabled": True, "emails": ["admin@beta.com"]}},
            {"name": "Cisco ASA Firewall", "type": "firewall", "ip": "172.16.1.1", "port": 443, "protocol": "https", "tenant_id": "cisco-systems", "notifications": {"enabled": True, "emails": ["aspundir@cisco.com", "security@cisco.com"]}},
            {"name": "IOS Router", "type": "router", "ip": "172.16.1.2", "port": 161, "protocol": "snmp", "tenant_id": "cisco-systems", "notifications": {"enabled": True, "emails": ["netops@cisco.com"]}},
            {"name": "Demo Web Server", "type": "web-server", "ip": "10.0.0.100", "port": 80, "protocol": "http", "tenant_id": "demo-org", "notifications": {"enabled": True, "emails": ["admin@demo.com"]}}
        ]
        
        for source_data in sources_data:
            source = Source(**source_data)
            db.add(source)
        
        # Create notifications
        notifications_data = [
            {"message": "High CPU usage detected on Web Server", "severity": "warning", "tenant_id": "acme-corp", "meta_data": {"cpu_usage": "85%"}},
            {"message": "Suspicious login attempt blocked", "severity": "critical", "tenant_id": "acme-corp", "meta_data": {"ip": "192.168.1.50"}},
            {"message": "System backup completed successfully", "severity": "info", "tenant_id": "acme-corp", "is_read": True, "meta_data": {"backup_size": "2.3GB"}},
            {"message": "Firewall rule updated", "severity": "info", "tenant_id": "beta-industries", "meta_data": {"rule_id": "FW-001"}},
            {"message": "Network intrusion detected", "severity": "critical", "tenant_id": "cisco-systems", "meta_data": {"source_ip": "172.16.1.50"}},
            {"message": "Router configuration backup", "severity": "info", "tenant_id": "cisco-systems", "is_read": True, "meta_data": {"device": "IOS-Router-01"}},
            {"message": "Demo alert - System monitoring", "severity": "info", "tenant_id": "demo-org", "meta_data": {"status": "monitoring"}}
        ]
        
        for notif_data in notifications_data:
            notification = Notification(**notif_data)
            db.add(notification)
        
        # Create reports
        reports_data = [
            {"title": "Security Summary Report", "summary": "Weekly security overview", "report_type": "security", "tenant_id": "acme-corp", "generated_by": "system", "data": {"total_events": 1250, "threats_blocked": 15}},
            {"title": "Threat Analysis Report", "summary": "Analysis of recent security threats", "report_type": "threat", "tenant_id": "acme-corp", "generated_by": "admin", "data": {"threats_detected": 8, "false_positives": 2}},
            {"title": "Network Security Report", "summary": "Network security assessment", "report_type": "network", "tenant_id": "beta-industries", "generated_by": "system", "data": {"vulnerabilities": 3, "patches_needed": 5}},
            {"title": "Cisco Infrastructure Report", "summary": "Cisco network infrastructure analysis", "report_type": "infrastructure", "tenant_id": "cisco-systems", "generated_by": "admin", "data": {"devices_monitored": 25, "uptime": "99.9%"}},
            {"title": "Demo Security Report", "summary": "Demo security overview", "report_type": "security", "tenant_id": "demo-org", "generated_by": "system", "data": {"events": 100, "alerts": 5}}
        ]
        
        for report_data in reports_data:
            report = Report(**report_data)
            db.add(report)
        
        # Commit all changes
        db.commit()
        print("Database initialized successfully with sample data")
        
        # Update tenant counts
        for tenant_id in ["acme-corp", "beta-industries", "cisco-systems", "demo-org"]:
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
            if tenant:
                tenant.user_count = db.query(User).filter(User.tenant_id == tenant_id).count()
                tenant.sources_count = db.query(Source).filter(Source.tenant_id == tenant_id).count()
        
        db.commit()
        db.close()
        return True
        
    except Exception as e:
        print(f"Database initialization failed: {e}")
        if 'db' in locals():
            db.rollback()
            db.close()
        return False

# Make models available for import
if DATABASE_AVAILABLE:
    __all__ = ["get_db", "init_db", "Tenant", "User", "Source", "Notification", "Report", "AuthenticationEvent", "UserBehaviorBaseline", "DetectionRule", "SecurityAlert", "CorrelationEvent", "DATABASE_AVAILABLE"]
else:
    __all__ = ["get_db", "init_db", "DATABASE_AVAILABLE"]

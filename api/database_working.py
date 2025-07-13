from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
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
        siem_config = relationship("TenantConfig", back_populates="tenant", uselist=False)

    class TenantConfig(Base):
        __tablename__ = "tenant_configs"
        
        id = Column(Integer, primary_key=True, index=True)
        tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, unique=True)
        siem_server_ip = Column(String, nullable=False)
        siem_server_port = Column(Integer, nullable=False, default=514)
        siem_protocol = Column(String, nullable=False, default="udp")  # udp, tcp, tls
        syslog_format = Column(String, nullable=False, default="rfc3164")  # rfc3164, rfc5424, cisco
        facility = Column(String, default="local0")
        severity = Column(String, default="info")
        enabled = Column(Boolean, default=True)
        setup_instructions = Column(Text)
        last_configured = Column(DateTime, default=datetime.utcnow)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        tenant = relationship("Tenant", back_populates="siem_config")

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
        if existing_tenants > 0:
            print("Database already initialized with sample data")
            db.close()
            return True
        
        print("Initializing database with sample data...")
        
        # Create tenants
        tenants_data = [
            {"id": "acme-corp", "name": "Acme Corporation", "description": "Technology company"},
            {"id": "beta-industries", "name": "Beta Industries", "description": "Manufacturing company"},
            {"id": "cisco-systems", "name": "Cisco Systems", "description": "Networking and cybersecurity company"},
            {"id": "demo-org", "name": "Demo Organization", "description": "Demo organization for testing"}
        ]
        
        for tenant_data in tenants_data:
            tenant = Tenant(**tenant_data)
            db.add(tenant)
        
        # Create users
        users_data = [
            {"id": "admin@acme.com", "email": "admin@acme.com", "password": "admin123", "name": "Acme Admin", "tenant_id": "acme-corp", "role": "admin", "tenants_access": ["acme-corp"]},
            {"id": "user@acme.com", "email": "user@acme.com", "password": "user123", "name": "Acme User", "tenant_id": "acme-corp", "role": "user", "tenants_access": ["acme-corp"]},
            {"id": "admin@beta.com", "email": "admin@beta.com", "password": "admin123", "name": "Beta Admin", "tenant_id": "beta-industries", "role": "admin", "tenants_access": ["beta-industries"]},
            {"id": "aspundir@cisco.com", "email": "aspundir@cisco.com", "password": "password123", "name": "Aspundir Singh", "tenant_id": "cisco-systems", "role": "admin", "tenants_access": ["cisco-systems"]},
            {"id": "admin@demo.com", "email": "admin@demo.com", "password": "demo123", "name": "Demo Admin", "tenant_id": "demo-org", "role": "admin", "tenants_access": ["demo-org"]},
            {"id": "user@demo.com", "email": "user@demo.com", "password": "demo123", "name": "Demo User", "tenant_id": "demo-org", "role": "user", "tenants_access": ["demo-org"]}
        ]
        
        for user_data in users_data:
            user = User(**user_data)
            db.add(user)
        
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
        
        # Create tenant SIEM configurations
        tenant_configs_data = [
            {
                "tenant_id": "acme-corp",
                "siem_server_ip": "192.168.1.10",
                "siem_server_port": 514,
                "siem_protocol": "udp",
                "syslog_format": "rfc3164",
                "facility": "local0",
                "severity": "info",
                "enabled": True,
                "setup_instructions": "Configure your devices to send syslog to 192.168.1.10:514 using UDP protocol with RFC3164 format."
            },
            {
                "tenant_id": "beta-industries",
                "siem_server_ip": "10.0.1.10",
                "siem_server_port": 515,
                "siem_protocol": "udp",
                "syslog_format": "rfc5424",
                "facility": "local1",
                "severity": "info",
                "enabled": True,
                "setup_instructions": "Configure your devices to send syslog to 10.0.1.10:515 using UDP protocol with RFC5424 format."
            },
            {
                "tenant_id": "cisco-systems",
                "siem_server_ip": "172.16.1.10",
                "siem_server_port": 516,
                "siem_protocol": "tcp",
                "syslog_format": "cisco",
                "facility": "local2",
                "severity": "info",
                "enabled": True,
                "setup_instructions": "Configure your Cisco devices to send syslog to 172.16.1.10:516 using TCP protocol with Cisco format."
            },
            {
                "tenant_id": "demo-org",
                "siem_server_ip": "10.0.0.10",
                "siem_server_port": 517,
                "siem_protocol": "udp",
                "syslog_format": "rfc3164",
                "facility": "local3",
                "severity": "info",
                "enabled": True,
                "setup_instructions": "Configure your devices to send syslog to 10.0.0.10:517 using UDP protocol with RFC3164 format."
            }
        ]
        
        for config_data in tenant_configs_data:
            config = TenantConfig(**config_data)
            db.add(config)
        
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
    __all__ = ["get_db", "init_db", "Tenant", "TenantConfig", "User", "Source", "Notification", "Report", "DATABASE_AVAILABLE"]
else:
    __all__ = ["get_db", "init_db", "DATABASE_AVAILABLE"]

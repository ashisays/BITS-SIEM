from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
import os

# Database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siempassword@db:5432/siemdb")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Database Models
class Tenant(Base):
    __tablename__ = "tenants"
    
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    status = Column(String, default="active")
    description = Column(Text)
    user_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    users = relationship("User", back_populates="tenant")
    sources = relationship("Source", back_populates="tenant")
    notifications = relationship("Notification", back_populates="tenant")
    reports = relationship("Report", back_populates="tenant")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)  # In production, use proper password hashing
    role = Column(String, nullable=False, default="user")
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    tenants_access = Column(JSON, default=list)  # List of tenant IDs user can access
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
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
    notifications = Column(JSON, default=dict)  # Notification settings
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    tenant = relationship("Tenant", back_populates="sources")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    message = Column(Text, nullable=False)
    severity = Column(String, default="info")
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=True)
    is_read = Column(Boolean, default=False)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    tenant = relationship("Tenant", back_populates="notifications")
    source = relationship("Source")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    summary = Column(Text)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    report_type = Column(String, default="security")
    data = Column(JSON, default=dict)
    generated_by = Column(String)  # User ID or system
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    tenant = relationship("Tenant", back_populates="reports")

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database
def init_db():
    """Initialize database with sample data"""
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Check if tenants already exist
        if db.query(Tenant).first():
            return  # Database already initialized
        
        # Create sample tenants
        tenant1 = Tenant(
            id="acme-corp",
            name="Acme Corporation",
            status="active",
            description="Leading technology company",
            user_count=0
        )
        tenant2 = Tenant(
            id="beta-industries",
            name="Beta Industries",
            status="active",
            description="Manufacturing and logistics",
            user_count=0
        )
        
        db.add(tenant1)
        db.add(tenant2)
        db.flush()  # Get IDs
        
        # Create sample users
        users_data = [
            {
                "email": "admin@acme.com",
                "name": "Acme Admin",
                "password": "admin123",
                "role": "admin",
                "tenant_id": "acme-corp",
                "tenants_access": ["acme-corp"]
            },
            {
                "email": "admin@beta.com",
                "name": "Beta Admin",
                "password": "admin123",
                "role": "admin",
                "tenant_id": "beta-industries",
                "tenants_access": ["beta-industries"]
            },
            {
                "email": "user@acme.com",
                "name": "Acme User",
                "password": "user123",
                "role": "user",
                "tenant_id": "acme-corp",
                "tenants_access": ["acme-corp"]
            },
            {
                "email": "user@beta.com",
                "name": "Beta User",
                "password": "user123",
                "role": "user",
                "tenant_id": "beta-industries",
                "tenants_access": ["beta-industries"]
            },
            {
                "email": "superadmin@system.com",
                "name": "Super Admin",
                "password": "super123",
                "role": "superadmin",
                "tenant_id": "acme-corp",
                "tenants_access": ["acme-corp", "beta-industries"]
            }
        ]
        
        for user_data in users_data:
            user = User(**user_data)
            db.add(user)
        
        # Update tenant user counts
        tenant1.user_count = 2  # admin@acme.com, user@acme.com
        tenant2.user_count = 2  # admin@beta.com, user@beta.com
        
        # Create sample sources
        sources_data = [
            {
                "name": "Web Server",
                "type": "web-server",
                "ip": "192.168.1.100",
                "port": 80,
                "protocol": "http",
                "status": "active",
                "tenant_id": "acme-corp",
                "notifications": {
                    "enabled": True,
                    "emails": ["admin@acme.com", "security@acme.com"]
                }
            },
            {
                "name": "Database Server",
                "type": "database",
                "ip": "192.168.1.200",
                "port": 3306,
                "protocol": "tcp",
                "status": "active",
                "tenant_id": "acme-corp",
                "notifications": {
                    "enabled": True,
                    "emails": ["dba@acme.com"]
                }
            },
            {
                "name": "Firewall",
                "type": "firewall",
                "ip": "10.0.1.1",
                "port": 514,
                "protocol": "udp",
                "status": "warning",
                "tenant_id": "beta-industries",
                "notifications": {
                    "enabled": True,
                    "emails": ["admin@beta.com"]
                }
            }
        ]
        
        for source_data in sources_data:
            source = Source(**source_data)
            db.add(source)
        
        # Create sample notifications
        notifications_data = [
            {
                "message": "High CPU usage detected on Web Server",
                "severity": "warning",
                "tenant_id": "acme-corp",
                "metadata": {"cpu_usage": "85%", "threshold": "80%"}
            },
            {
                "message": "Suspicious login attempt blocked",
                "severity": "critical",
                "tenant_id": "acme-corp",
                "metadata": {"ip": "192.168.1.50", "attempts": 5}
            },
            {
                "message": "System backup completed successfully",
                "severity": "info",
                "tenant_id": "beta-industries",
                "metadata": {"backup_size": "2.3GB", "duration": "15min"}
            }
        ]
        
        for notif_data in notifications_data:
            notification = Notification(**notif_data)
            db.add(notification)
        
        # Create sample reports
        reports_data = [
            {
                "title": "Security Summary Report",
                "summary": "Weekly security overview for Acme Corporation",
                "tenant_id": "acme-corp",
                "report_type": "security",
                "generated_by": "system",
                "data": {
                    "total_events": 1250,
                    "critical_alerts": 3,
                    "warnings": 15,
                    "period": "last_7_days"
                }
            },
            {
                "title": "Threat Analysis Report",
                "summary": "Analysis of recent security threats and incidents",
                "tenant_id": "beta-industries",
                "report_type": "threat",
                "generated_by": "admin@beta.com",
                "data": {
                    "threats_detected": 8,
                    "threats_blocked": 7,
                    "false_positives": 2
                }
            }
        ]
        
        for report_data in reports_data:
            report = Report(**report_data)
            db.add(report)
        
        db.commit()
        print("Database initialized successfully with sample data")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()

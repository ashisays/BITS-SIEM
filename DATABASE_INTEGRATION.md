# BITS-SIEM Database Integration Guide

This guide explains how to integrate other services with the BITS-SIEM PostgreSQL database for shared data access.

## 🗄️ Database Overview

**Connection Details:**
- **Host**: `db` (Docker) or `localhost` (local)
- **Port**: `5432`
- **Database**: `siemdb`
- **Username**: `siem`
- **Password**: `siempassword`
- **URL**: `postgresql+psycopg2://siem:siempassword@db:5432/siemdb`

## 📊 Database Schema

### Tables Overview
- **tenants**: Organizations using the SIEM system
- **users**: User accounts with authentication and roles
- **sources**: Security data sources (servers, firewalls, etc.)
- **notifications**: Security alerts and system messages
- **reports**: Generated security reports and analysis

### Sample Data
The database is initialized with sample data for 4 organizations:
- **Acme Corporation** (`acme-corp`)
- **Beta Industries** (`beta-industries`) 
- **Cisco Systems** (`cisco-systems`)
- **Demo Organization** (`demo-org`)

## 🔧 Integration Methods

### Method 1: Direct Database Access

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://siem:siempassword@db:5432/siemdb")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Use the session
db = SessionLocal()
# Your database operations here
db.close()
```

### Method 2: Import BITS-SIEM Database Module

```python
from api.database import get_db, Tenant, User, Source, Notification, Report

# Use with FastAPI dependency injection
def my_endpoint(db = Depends(get_db)):
    tenants = db.query(Tenant).all()
    return tenants
```

### Method 3: Copy Database Models

Copy the model definitions from `api/database.py` to your service:

```python
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    # ... other fields
```

## 📋 Sample Queries

### Get All Tenants
```python
tenants = db.query(Tenant).all()
for tenant in tenants:
    print(f"Organization: {tenant.name} ({tenant.id})")
```

### Get Users for a Tenant
```python
tenant_id = "acme-corp"
users = db.query(User).filter(User.tenant_id == tenant_id).all()
for user in users:
    print(f"User: {user.name} ({user.email}) - {user.role}")
```

### Get Sources for a Tenant
```python
tenant_id = "cisco-systems"
sources = db.query(Source).filter(Source.tenant_id == tenant_id).all()
for source in sources:
    print(f"Source: {source.name} ({source.type}) - {source.ip}:{source.port}")
```

### Get Recent Notifications
```python
from datetime import datetime, timedelta

recent = datetime.now() - timedelta(days=7)
notifications = db.query(Notification).filter(
    Notification.created_at >= recent
).order_by(Notification.created_at.desc()).all()

for notif in notifications:
    print(f"Alert: {notif.message} ({notif.severity})")
```

## 🚀 Service Examples

### Ingestion Service
```python
# Add new security events to notifications
def add_security_event(tenant_id: str, message: str, severity: str, metadata: dict):
    db = SessionLocal()
    notification = Notification(
        message=message,
        severity=severity,
        tenant_id=tenant_id,
        metadata=metadata
    )
    db.add(notification)
    db.commit()
    db.close()
```

### Processing Service
```python
# Process sources and update their status
def update_source_status(source_id: int, status: str):
    db = SessionLocal()
    source = db.query(Source).filter(Source.id == source_id).first()
    if source:
        source.status = status
        source.last_activity = datetime.utcnow()
        db.commit()
    db.close()
```

### Notification Service
```python
# Get sources with email notifications enabled
def get_notification_sources(tenant_id: str):
    db = SessionLocal()
    sources = db.query(Source).filter(
        Source.tenant_id == tenant_id,
        Source.notifications['enabled'].astext.cast(Boolean) == True
    ).all()
    
    notification_list = []
    for source in sources:
        emails = source.notifications.get('emails', [])
        notification_list.append({
            'source_name': source.name,
            'emails': emails
        })
    
    db.close()
    return notification_list
```

## 🔄 Database Initialization

### Option 1: Use Initialization Script
```bash
cd api
python init_database.py
```

### Option 2: Import and Call
```python
from api.database import init_db

success = init_db()
if success:
    print("Database ready!")
```

## 🏗️ Docker Integration

### Environment Variables
```yaml
services:
  your-service:
    build: ./your-service
    environment:
      DATABASE_URL: postgresql+psycopg2://siem:siempassword@db:5432/siemdb
    depends_on:
      - db
```

### Docker Compose Addition
```yaml
  your-service:
    build: ./your-service
    environment:
      DATABASE_URL: postgresql+psycopg2://siem:siempassword@db:5432/siemdb
    depends_on:
      - db
    ports:
      - "8080:8080"
```

## 🛡️ Security Considerations

### Production Setup
1. **Change Default Credentials**: Update database username/password
2. **Use Environment Variables**: Never hardcode credentials
3. **Enable SSL**: Use SSL connections in production
4. **Limit Access**: Restrict database access to authorized services only
5. **Hash Passwords**: User passwords are currently plain text - implement hashing

### Example Production Config
```python
DATABASE_URL = os.getenv("DATABASE_URL")  # Required in production
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")
```

## 📈 Monitoring & Maintenance

### Health Checks
```python
def check_database_health():
    try:
        db = SessionLocal()
        # Simple query to test connection
        db.execute("SELECT 1")
        db.close()
        return True
    except Exception as e:
        print(f"Database health check failed: {e}")
        return False
```

### Performance Monitoring
- Monitor connection pool usage
- Track query performance
- Set up alerts for failed connections
- Regular database maintenance (vacuum, analyze)

## 🤝 Contributing

### Adding New Tables
1. Define model in `database.py`
2. Create migration with Alembic
3. Update initialization script
4. Document new schema

### Sample Migration
```bash
cd api
alembic revision --autogenerate -m "Add new table"
alembic upgrade head
```

## 📞 Support

For issues or questions about database integration:
1. Check database logs in Docker
2. Verify connection strings
3. Ensure PostgreSQL is running
4. Check firewall/network settings

## 🎯 Benefits of Shared Database

- **Data Consistency**: Single source of truth across all services
- **Real-time Updates**: Changes visible immediately to all services
- **Scalability**: Can handle multiple services accessing same data
- **Backup/Recovery**: Centralized data backup and disaster recovery
- **Analytics**: Easy to run complex queries across all data
- **Multi-tenancy**: Built-in organization isolation

# BITS-SIEM Database Schema Documentation

## 🗄️ Overview
BITS-SIEM uses PostgreSQL database with SQLAlchemy ORM for data persistence. The schema is designed to support multi-tenant security information and event management with role-based access control.

## 🏗️ Database Configuration
- **Database**: PostgreSQL 13+
- **ORM**: SQLAlchemy with declarative_base
- **Connection Pool**: Pre-ping enabled with 300s recycle
- **Default URL**: `postgresql+psycopg2://siem:siempassword@db:5432/siemdb`

## 📊 Entity Relationship Diagram

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│   TENANTS   │◄─────►│    USERS    │       │   SOURCES   │
│             │       │             │       │             │
│ id (PK)     │       │ id (PK)     │       │ id (PK)     │
│ name        │       │ email       │       │ name        │
│ description │       │ tenant_id(FK)│      │ tenant_id(FK)│
│ ...         │       │ ...         │       │ ...         │
└─────────────┘       └─────────────┘       └─────────────┘
       │                                           ▲
       │                                           │
       ▼                                           │
┌─────────────┐                           ┌─────────────┐
│NOTIFICATIONS│                           │   REPORTS   │
│             │                           │             │
│ id (PK)     │                           │ id (PK)     │
│ tenant_id(FK)│                          │ tenant_id(FK)│
│ ...         │                           │ ...         │
└─────────────┘                           └─────────────┘
```

## 🏢 Tables Schema

### 1. TENANTS
**Purpose**: Organizations using the SIEM system

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | String | PRIMARY KEY, INDEX | Unique tenant identifier (e.g., "acme-corp") |
| `name` | String | NOT NULL | Organization display name |
| `description` | Text | NULLABLE | Optional organization description |
| `user_count` | Integer | DEFAULT 0 | Number of users in organization |
| `sources_count` | Integer | DEFAULT 0 | Number of security sources |
| `status` | String | DEFAULT "active" | Tenant status (active/inactive) |
| `created_at` | DateTime | DEFAULT utcnow | Record creation timestamp |
| `updated_at` | DateTime | DEFAULT utcnow, ON UPDATE | Last modification timestamp |

**Relationships:**
- One-to-Many with `users`, `sources`, `notifications`, `reports`

**Sample Data:**
- `acme-corp` - Acme Corporation
- `beta-industries` - Beta Industries
- `cisco-systems` - Cisco Systems
- `demo-org` - Demo Organization
- `bits-internal` - BITS Internal (SRE Team)

---

### 2. USERS
**Purpose**: User accounts with authentication and tenant associations

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | String | PRIMARY KEY, INDEX | Unique user identifier (UUID) |
| `email` | String | UNIQUE, INDEX, NOT NULL | User email address (login) |
| `name` | String | NOT NULL | User display name |
| `password` | String | NOT NULL | Password hash (bcrypt recommended) |
| `role` | String | NOT NULL, DEFAULT "user" | User role (admin/user/sre) |
| `tenant_id` | String | FOREIGN KEY, NOT NULL | Primary tenant association |
| `tenants_access` | JSON | NULLABLE | Additional tenant access list |
| `is_active` | Boolean | DEFAULT True | Account status flag |
| `created_at` | DateTime | DEFAULT utcnow | Account creation timestamp |
| `updated_at` | DateTime | DEFAULT utcnow, ON UPDATE | Last modification timestamp |

**Relationships:**
- Many-to-One with `tenants` (via `tenant_id`)

**User Roles:**
- `admin` - Tenant administrator with full access to tenant data
- `user` - Regular user with read access to tenant data
- `sre` - Site Reliability Engineer with cross-tenant access

**Sample Data:**
- Admin users for each organization
- Regular users for each organization
- SRE user with multi-tenant access

---

### 3. SOURCES
**Purpose**: Security data sources (servers, firewalls, databases, etc.)

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY, INDEX, AUTO INCREMENT | Unique source identifier |
| `name` | String | NOT NULL | Human-readable source name |
| `type` | String | NOT NULL | Source type (web_server/database/firewall/router) |
| `ip` | String | NOT NULL | IP address of the source |
| `port` | Integer | NOT NULL | Port number for connection |
| `protocol` | String | NOT NULL | Communication protocol (HTTP/HTTPS/SSH/etc.) |
| `status` | String | DEFAULT "active" | Source status (active/inactive/error) |
| `tenant_id` | String | FOREIGN KEY, NOT NULL | Owning tenant |
| `notifications` | JSON | NULLABLE | Notification configuration settings |
| `last_activity` | DateTime | DEFAULT utcnow | Last activity timestamp |
| `created_at` | DateTime | DEFAULT utcnow | Source creation timestamp |
| `updated_at` | DateTime | DEFAULT utcnow, ON UPDATE | Last modification timestamp |

**Relationships:**
- Many-to-One with `tenants` (via `tenant_id`)

**Source Types:**
- `web_server` - Web application servers
- `database` - Database servers
- `firewall` - Network firewalls
- `router` - Network routers

**Sample Data:**
- Web servers (Apache, Nginx)
- Database servers (MySQL, PostgreSQL)
- Network devices (Cisco ASA, pfSense)

---

### 4. NOTIFICATIONS
**Purpose**: Security alerts and system messages

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY, INDEX, AUTO INCREMENT | Unique notification identifier |
| `message` | Text | NOT NULL | Notification message content |
| `severity` | String | NOT NULL, DEFAULT "info" | Alert severity level |
| `tenant_id` | String | FOREIGN KEY, NOT NULL | Target tenant |
| `is_read` | Boolean | DEFAULT False | Read status flag |
| `meta_data` | JSON | NULLABLE | Additional notification metadata |
| `created_at` | DateTime | DEFAULT utcnow | Notification creation timestamp |

**Relationships:**
- Many-to-One with `tenants` (via `tenant_id`)

**Severity Levels:**
- `critical` - Critical security incidents requiring immediate attention
- `warning` - Important security events that need review
- `info` - Informational messages and system status updates

**Sample Data:**
- Security alerts for failed login attempts
- System maintenance notifications
- Threat detection warnings

---

### 5. REPORTS
**Purpose**: Generated security reports and analysis

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY, INDEX, AUTO INCREMENT | Unique report identifier |
| `title` | String | NOT NULL | Report title |
| `summary` | Text | NULLABLE | Executive summary of the report |
| `report_type` | String | NOT NULL | Type of security report |
| `tenant_id` | String | FOREIGN KEY, NOT NULL | Owning tenant |
| `generated_by` | String | NOT NULL | User who generated the report |
| `data` | JSON | NULLABLE | Report data and statistics |
| `created_at` | DateTime | DEFAULT utcnow | Report generation timestamp |

**Relationships:**
- Many-to-One with `tenants` (via `tenant_id`)

**Report Types:**
- `security_summary` - Overall security posture summary
- `threat_analysis` - Threat detection and analysis
- `vulnerability_scan` - System vulnerability assessment
- `incident_response` - Security incident documentation

**Sample Data:**
- Weekly security summaries
- Threat analysis reports
- Vulnerability assessment reports

## 🔧 Database Operations

### Connection Management
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql+psycopg2://siem:siempassword@db:5432/siemdb"
engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

### Session Usage
```python
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### Multi-Tenant Queries
All queries should filter by tenant context:
```python
# Get user's sources
sources = db.query(Source).filter(Source.tenant_id == user_tenant_id).all()

# Get tenant notifications
notifications = db.query(Notification).filter(
    Notification.tenant_id == user_tenant_id
).order_by(Notification.created_at.desc()).all()
```

## 🔐 Security Considerations

### Data Isolation
- All data operations are tenant-scoped
- Cross-tenant access restricted to SRE role
- Foreign key constraints enforce referential integrity

### Authentication
- Passwords should be hashed using bcrypt
- JWT tokens for session management
- Role-based access control (RBAC)

### Database Security
- Connection pooling with pre-ping health checks
- Prepared statements prevent SQL injection
- Database user has minimal required permissions

## 🚀 Deployment Notes

### Database Initialization
The database is automatically initialized with sample data on first startup:
```python
from database import init_db
success = init_db()
```

### Environment Variables
```bash
DATABASE_URL=postgresql+psycopg2://siem:siempassword@db:5432/siemdb
```

### Migration Support
SQLAlchemy models support Alembic migrations for schema versioning:
```bash
alembic init alembic
alembic revision --autogenerate -m "Initial migration"
alembic upgrade head
```

## 📈 Performance Considerations

### Indexing Strategy
- Primary keys are automatically indexed
- Email field has unique index for fast user lookup
- Tenant ID fields should be indexed for multi-tenant queries
- Consider composite indexes for common query patterns

### Query Optimization
- Use eager loading for relationships when appropriate
- Implement pagination for large result sets
- Consider read replicas for reporting workloads

### Monitoring
- Track connection pool usage
- Monitor slow queries
- Set up database performance metrics

## 🔄 Backup and Recovery

### Backup Strategy
```bash
# Full database backup
pg_dump -h localhost -U siem -d siemdb > backup.sql

# Compressed backup
pg_dump -h localhost -U siem -d siemdb | gzip > backup.sql.gz
```

### Recovery Process
```bash
# Restore from backup
psql -h localhost -U siem -d siemdb < backup.sql
```

## 📝 Change Log

### Version History
- **v1.0.0** - Initial schema with multi-tenant support
- **v1.1.0** - Added SRE role and cross-tenant access
- **v1.2.0** - Enhanced notification system with metadata
- **v1.3.0** - Added comprehensive indexing and performance optimizations

---

*Last Updated: 2025-01-14*  
*Database Version: PostgreSQL 13+*  
*ORM Version: SQLAlchemy 1.4+*

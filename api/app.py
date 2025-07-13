from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from jose import jwt, JWTError
import time
import asyncio
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from config import config

# Try to import database functionality
try:
    from database_working import (
        get_db, init_db, 
        Tenant as TenantModel, 
        TenantConfig as TenantConfigModel,
        User as UserModel, 
        Source as SourceModel,
        Notification as NotificationModel,
        Report as ReportModel,
        DATABASE_AVAILABLE,
        SessionLocal
    )
    print(f"Database support: {DATABASE_AVAILABLE}")
except Exception as e:
    print(f"Database import failed: {e}")
    DATABASE_AVAILABLE = False
    def get_db(): return None
    def init_db(): return False

SECRET_KEY = config.security.jwt_secret
ALGORITHM = config.security.jwt_algorithm

app = FastAPI(title="BITS-SIEM API", version="1.0.0")

# CSRF Protection
class CSRFProtection:
    def __init__(self):
        self.csrf_tokens = {}  # In production, use Redis or database
    
    def generate_token(self, user_id: str) -> str:
        """Generate a CSRF token for a user"""
        token = secrets.token_urlsafe(32)
        self.csrf_tokens[user_id] = {
            'token': token,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24)
        }
        return token
    
    def validate_token(self, user_id: str, token: str) -> bool:
        """Validate a CSRF token"""
        if user_id not in self.csrf_tokens:
            return False
        
        stored_data = self.csrf_tokens[user_id]
        
        # Check if token has expired
        if datetime.now() > stored_data['expires_at']:
            del self.csrf_tokens[user_id]
            return False
        
        # Check if token matches
        return secrets.compare_digest(stored_data['token'], token)
    
    def invalidate_token(self, user_id: str):
        """Invalidate a user's CSRF token"""
        if user_id in self.csrf_tokens:
            del self.csrf_tokens[user_id]

csrf_protection = CSRFProtection()

# Validation error handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    body = await request.body()
    print(f"Validation error on {request.method} {request.url}")
    print(f"Request body: {body.decode('utf-8') if body else 'Empty'}")
    print(f"Validation errors: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": body.decode('utf-8') if body else 'Empty'}
    )

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# CSRF middleware
@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    # Skip CSRF check for GET requests and authentication endpoints
    if request.method == "GET" or request.url.path.startswith("/api/auth/"):
        response = await call_next(request)
        return response
    
    # Get user from JWT token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        response = await call_next(request)
        return response
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        
        # Check CSRF token for state-changing operations
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token or not csrf_protection.validate_token(user_id, csrf_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid or missing CSRF token"}
            )
        
    except JWTError:
        pass  # Let the endpoint handle JWT validation
    
    response = await call_next(request)
    return response

# Fallback in-memory data (used when database is not available)
def get_fallback_users():
    """Generate fallback users with system-generated passwords"""
    tenant_configs = config.get_sample_tenant_configs()
    
    return {
        "admin@acme.com": {
            "email": "admin@acme.com",
            "password": tenant_configs['acme-corp']['password'],
            "name": "Acme Admin",
            "tenantId": "acme-corp",
            "role": "admin",
            "tenants": ["acme-corp"],
            "is_active": True
        },
        "user@acme.com": {
            "email": "user@acme.com",
            "password": config.generate_secure_password(12),
            "name": "Acme User",
            "tenantId": "acme-corp",
            "role": "user",
            "tenants": ["acme-corp"],
            "is_active": True
        },
        "admin@beta.com": {
            "email": "admin@beta.com",
            "password": tenant_configs['beta-industries']['password'],
            "name": "Beta Admin",
            "tenantId": "beta-industries",
            "role": "admin",
            "tenants": ["beta-industries"],
            "is_active": True
        },
        "aspundir@cisco.com": {
            "email": "aspundir@cisco.com",
            "password": tenant_configs['cisco-systems']['password'],
            "name": "Aspundir Singh",
            "tenantId": "cisco-systems",
            "role": "admin",
            "tenants": ["cisco-systems"],
            "is_active": True
        },
        "admin@demo.com": {
            "email": "admin@demo.com",
            "password": tenant_configs['demo-org']['password'],
            "name": "Demo Admin",
            "tenantId": "demo-org",
            "role": "admin",
            "tenants": ["demo-org"],
            "is_active": True
        },
        "user@demo.com": {
            "email": "user@demo.com",
            "password": config.generate_secure_password(12),
            "name": "Demo User",
            "tenantId": "demo-org",
            "role": "user",
            "tenants": ["demo-org"],
            "is_active": True
        },
        "sre@bits.com": {
            "email": "sre@bits.com",
            "password": tenant_configs['bits-internal']['password'],
            "name": "BITS SRE",
            "tenantId": "bits-internal",
            "role": "sre",
            "tenants": ["bits-internal", "acme-corp", "beta-industries", "cisco-systems", "demo-org"],
            "is_active": True
        }
    }

fallback_users = get_fallback_users()

fallback_sources = {
    "acme-corp": [
        {"id": 1, "name": "Web Server", "type": "web-server", "ip": "192.168.1.100", "port": 80, "protocol": "http", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "acme-corp", "notifications": {"enabled": True, "emails": ["admin@acme.com", "security@acme.com"]}},
        {"id": 2, "name": "Database Server", "type": "database", "ip": "192.168.1.200", "port": 3306, "protocol": "tcp", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "acme-corp", "notifications": {"enabled": True, "emails": ["dba@acme.com"]}}
    ],
    "beta-industries": [
        {"id": 3, "name": "Firewall", "type": "firewall", "ip": "10.0.1.1", "port": 514, "protocol": "udp", "status": "warning", "lastActivity": (datetime.now() - timedelta(hours=1)).isoformat(), "tenant": "beta-industries", "notifications": {"enabled": True, "emails": ["admin@beta.com"]}}
    ],
    "cisco-systems": [
        {"id": 4, "name": "Cisco ASA Firewall", "type": "firewall", "ip": "172.16.1.1", "port": 443, "protocol": "https", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "cisco-systems", "notifications": {"enabled": True, "emails": ["aspundir@cisco.com", "security@cisco.com"]}},
        {"id": 5, "name": "IOS Router", "type": "router", "ip": "172.16.1.2", "port": 161, "protocol": "snmp", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "cisco-systems", "notifications": {"enabled": True, "emails": ["netops@cisco.com"]}}
    ],
    "demo-org": [
        {"id": 6, "name": "Demo Web Server", "type": "web-server", "ip": "10.0.0.100", "port": 80, "protocol": "http", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "demo-org", "notifications": {"enabled": True, "emails": ["admin@demo.com"]}}
    ],
    "bits-internal": [
        {"id": 7, "name": "SRE Monitoring Server", "type": "monitoring", "ip": "172.20.0.10", "port": 9090, "protocol": "http", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "bits-internal", "notifications": {"enabled": True, "emails": ["sre@bits.com"]}},
        {"id": 8, "name": "BITS Internal API Gateway", "type": "api-gateway", "ip": "172.20.0.11", "port": 443, "protocol": "https", "status": "active", "lastActivity": datetime.now().isoformat(), "tenant": "bits-internal", "notifications": {"enabled": True, "emails": ["sre@bits.com"]}}
    ]
}

# Fallback notifications data
fallback_notifications = {
    "acme-corp": [
        {"id": 1, "message": "High CPU usage detected on Web Server", "timestamp": datetime.now().isoformat(), "tenant": "acme-corp", "severity": "warning", "isRead": False, "metadata": {"cpu_usage": "85%"}},
        {"id": 2, "message": "Suspicious login attempt blocked", "timestamp": datetime.now().isoformat(), "tenant": "acme-corp", "severity": "critical", "isRead": False, "metadata": {"ip": "192.168.1.50"}},
        {"id": 3, "message": "System backup completed successfully", "timestamp": datetime.now().isoformat(), "tenant": "acme-corp", "severity": "info", "isRead": True, "metadata": {"backup_size": "2.3GB"}}
    ],
    "beta-industries": [
        {"id": 4, "message": "Firewall rule updated", "timestamp": datetime.now().isoformat(), "tenant": "beta-industries", "severity": "info", "isRead": False, "metadata": {"rule_id": "FW-001"}},
        {"id": 5, "message": "Network intrusion attempt detected", "timestamp": datetime.now().isoformat(), "tenant": "beta-industries", "severity": "critical", "isRead": False, "metadata": {"source_ip": "10.0.1.50"}}
    ],
    "cisco-systems": [
        {"id": 6, "message": "Router configuration backup completed", "timestamp": datetime.now().isoformat(), "tenant": "cisco-systems", "severity": "info", "isRead": True, "metadata": {"device": "IOS-Router-01"}},
        {"id": 7, "message": "ASA Firewall policy violation", "timestamp": datetime.now().isoformat(), "tenant": "cisco-systems", "severity": "warning", "isRead": False, "metadata": {"policy": "DMZ-BLOCK"}}
    ],
    "demo-org": [
        {"id": 8, "message": "Demo alert - System monitoring active", "timestamp": datetime.now().isoformat(), "tenant": "demo-org", "severity": "info", "isRead": False, "metadata": {"status": "monitoring"}}
    ],
    "bits-internal": [
        {"id": 9, "message": "SRE Dashboard - All systems operational", "timestamp": datetime.now().isoformat(), "tenant": "bits-internal", "severity": "info", "isRead": False, "metadata": {"uptime": "99.9%"}}
    ]
}

# Initialize on startup
@app.on_event("startup")
async def startup_event():
    print("Starting BITS-SIEM API")
    if DATABASE_AVAILABLE:
        print("Attempting database initialization...")
        success = init_db()
        if success:
            print("✅ Database mode: PostgreSQL with persistent storage")
            print("📊 Data will be shared across all services")
            print("👤 SRE user should be available: sre@bits.com")
        else:
            print("⚠️  Database initialization failed, using fallback mode")
            print("👤 Using fallback mode - SRE user: sre@bits.com")
    else:
        print("⚠️  Database not available, using in-memory fallback mode")

# Pydantic Models
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str
    tenantName: str = None

class Source(BaseModel):
    name: str
    type: str
    ip: str
    port: int
    protocol: str
    notifications: dict = {"enabled": False, "emails": []}

class TenantConfig(BaseModel):
    siem_server_ip: str
    siem_server_port: int = 514
    siem_protocol: str = "udp"  # udp, tcp, tls
    syslog_format: str = "rfc3164"  # rfc3164, rfc5424, cisco
    facility: str = "local0"
    severity: str = "info"
    enabled: bool = True
    setup_instructions: str = ""

# JWT token creation
def create_jwt(user_data):
    if isinstance(user_data, dict):
        # Fallback data format
        payload = {
            "email": user_data["email"],
            "tenantId": user_data["tenantId"], 
            "role": user_data["role"],
            "name": user_data["name"],
            "user_id": user_data["email"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
    else:
        # Database model format
        payload = {
            "email": user_data.email,
            "tenantId": user_data.tenant_id,
            "role": user_data.role,
            "name": user_data.name,
            "user_id": user_data.id,
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        if DATABASE_AVAILABLE and db:
            # Database validation
            user = db.query(UserModel).filter(UserModel.email == email).first()
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="User not found or inactive")
            
            return {
                "email": user.email,
                "tenantId": user.tenant_id,
                "role": user.role,
                "name": user.name,
                "user_id": user.id
            }
        else:
            # Fallback validation
            user_data = fallback_users.get(email)
            if not user_data or not user_data.get("is_active", True):
                raise HTTPException(status_code=401, detail="User not found or inactive")
            
            return {
                "email": user_data["email"],
                "tenantId": user_data["tenantId"],
                "role": user_data["role"],
                "name": user_data["name"],
                "user_id": user_data["email"]
            }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Authentication endpoints
@app.post("/api/auth/register")
def register(register_data: RegisterRequest, db = Depends(get_db)):
    print(f"Registration attempt for: {register_data.email}")
    if DATABASE_AVAILABLE and db:
        print("Using database mode for registration")
        # Database registration
        existing_user = db.query(UserModel).filter(UserModel.email == register_data.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Generate tenant ID
        if register_data.tenantName:
            tenant_id = register_data.tenantName.lower().replace(" ", "-")
        else:
            domain = register_data.email.split('@')[1]
            tenant_id = domain.replace('.', '-')
        
        # Create or get tenant
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            tenant = TenantModel(
                id=tenant_id,
                name=register_data.tenantName or domain.replace('.', ' ').title(),
                description=f"Organization for {domain}"
            )
            db.add(tenant)
        
        # Create user
        user = UserModel(
            id=register_data.email,
            email=register_data.email,
            password=register_data.password,
            name=register_data.name,
            tenant_id=tenant_id,
            role="admin",
            tenants_access=[tenant_id]
        )
        db.add(user)
        db.commit()
        print(f"User created in database: {user.email} with tenant {user.tenant_id}")
        
    else:
        # Fallback registration
        print("Using fallback mode for registration")
        if register_data.email in fallback_users:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        if register_data.tenantName:
            tenant_id = register_data.tenantName.lower().replace(" ", "-")
        else:
            domain = register_data.email.split('@')[1]
            tenant_id = domain.replace('.', '-')
        
        fallback_users[register_data.email] = {
            "email": register_data.email,
            "password": register_data.password,
            "name": register_data.name,
            "tenantId": tenant_id,
            "role": "admin",
            "tenants": [tenant_id],
            "is_active": True
        }
        
        # Initialize empty sources
        if tenant_id not in fallback_sources:
            fallback_sources[tenant_id] = []
        
        print(f"User created in fallback: {register_data.email} with tenant {tenant_id}")
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(login_data: LoginRequest, db = Depends(get_db)):
    print(f"Login attempt for: {login_data.email}")
    if DATABASE_AVAILABLE and db:
        print("Using database mode for login")
        # Database login
        user = db.query(UserModel).filter(UserModel.email == login_data.email).first()
        
        if not user:
            print(f"User not found in database: {login_data.email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        print(f"User found: {user.email}, checking password...")
        if user.password != login_data.password:
            print(f"Password mismatch for {user.email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        if not user.is_active:
            print(f"User inactive: {user.email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        token = create_jwt(user)
        # Generate CSRF token
        csrf_token = csrf_protection.generate_token(user.email)
        
        return {
            "token": token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "tenantId": user.tenant_id,
                "role": user.role,
                "tenants": user.tenants_access or [user.tenant_id]
            },
            "csrf_token": csrf_token
        }
    else:
        # Fallback login
        print("Using fallback mode for login")
        user_data = fallback_users.get(login_data.email)
        
        if not user_data:
            print(f"User not found in fallback: {login_data.email}")
            print(f"Available users: {list(fallback_users.keys())}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
            
        print(f"User found in fallback: {user_data['email']}")
        if user_data["password"] != login_data.password:
            print(f"Password mismatch in fallback for {user_data['email']}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        if not user_data.get("is_active", True):
            raise HTTPException(status_code=401, detail="Account is inactive")
        
        token = create_jwt(user_data)
        # Generate CSRF token
        csrf_token = csrf_protection.generate_token(user_data["email"])
        
        return {
            "token": token,
            "user": {
                "id": user_data["email"],
                "name": user_data["name"],
                "email": user_data["email"],
                "tenantId": user_data["tenantId"],
                "role": user_data["role"],
                "tenants": user_data["tenants"]
            },
            "csrf_token": csrf_token
        }

# SIEM Data endpoints
@app.get("/api/sources")
def get_sources(current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    print(f"Getting sources for tenant: {user_tenant}")
    
    if DATABASE_AVAILABLE and db:
        print("Using database mode for get_sources")
        # Database sources
        sources = db.query(SourceModel).filter(SourceModel.tenant_id == user_tenant).all()
        print(f"Found {len(sources)} sources in database for tenant {user_tenant}")
        return [{
            "id": source.id,
            "name": source.name,
            "type": source.type,
            "ip": source.ip,
            "port": source.port,
            "protocol": source.protocol,
            "status": source.status,
            "lastActivity": source.last_activity.isoformat() if source.last_activity else None,
            "tenant": source.tenant_id,
            "notifications": source.notifications or {"enabled": False, "emails": []}
        } for source in sources]
    else:
        # Fallback sources
        print("Using fallback mode for get_sources")
        sources = fallback_sources.get(user_tenant, [])
        print(f"Found {len(sources)} sources in fallback for tenant {user_tenant}")
        print(f"Available fallback tenants: {list(fallback_sources.keys())}")
        return sources

@app.post("/api/sources")
def add_source(source: Source, current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    print(f"Adding source for tenant: {user_tenant}")
    print(f"Source data received: name={source.name}, type={source.type}, ip={source.ip}, port={source.port}, protocol={source.protocol}")
    print(f"Notifications: {source.notifications}")
    
    if DATABASE_AVAILABLE and db:
        print("Using database mode for add_source")
        # Database add source
        new_source = SourceModel(
            name=source.name,
            type=source.type,
            ip=source.ip,
            port=source.port,
            protocol=source.protocol,
            tenant_id=user_tenant,
            notifications=source.notifications,
            status="active"
        )
        db.add(new_source)
        db.commit()
        db.refresh(new_source)
        print(f"Source added to database: {new_source.name} (ID: {new_source.id})")
        
        return {
            "id": new_source.id,
            "name": new_source.name,
            "type": new_source.type,
            "ip": new_source.ip,
            "port": new_source.port,
            "protocol": new_source.protocol,
            "status": new_source.status,
            "lastActivity": new_source.last_activity.isoformat() if new_source.last_activity else None,
            "tenant": new_source.tenant_id,
            "notifications": new_source.notifications
        }
    else:
        # Fallback add source
        print("Using fallback mode for add_source")
        if user_tenant not in fallback_sources:
            fallback_sources[user_tenant] = []
            print(f"Created new tenant in fallback: {user_tenant}")
        
        # Get next ID
        all_sources = []
        for tenant_sources in fallback_sources.values():
            all_sources.extend(tenant_sources)
        next_id = max([s["id"] for s in all_sources], default=0) + 1
        
        new_source = {
            "id": next_id,
            "name": source.name,
            "type": source.type,
            "ip": source.ip,
            "port": source.port,
            "protocol": source.protocol,
            "status": "active",
            "lastActivity": datetime.now().isoformat(),
            "tenant": user_tenant,
            "notifications": source.notifications
        }
        
        fallback_sources[user_tenant].append(new_source)
        print(f"Source added to fallback: {new_source['name']} (ID: {new_source['id']})")
        return new_source

@app.put("/api/sources/{source_id}")
def update_source(source_id: int, source: Source, current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database update
        db_source = db.query(SourceModel).filter(
            SourceModel.id == source_id,
            SourceModel.tenant_id == user_tenant
        ).first()
        
        if not db_source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        db_source.name = source.name
        db_source.type = source.type
        db_source.ip = source.ip
        db_source.port = source.port
        db_source.protocol = source.protocol
        db_source.notifications = source.notifications
        db_source.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(db_source)
        
        return {
            "id": db_source.id,
            "name": db_source.name,
            "type": db_source.type,
            "ip": db_source.ip,
            "port": db_source.port,
            "protocol": db_source.protocol,
            "status": db_source.status,
            "lastActivity": db_source.last_activity.isoformat() if db_source.last_activity else None,
            "tenant": db_source.tenant_id,
            "notifications": db_source.notifications
        }
    else:
        # Fallback update
        tenant_sources = fallback_sources.get(user_tenant, [])
        for i, s in enumerate(tenant_sources):
            if s["id"] == source_id:
                fallback_sources[user_tenant][i].update({
                    "name": source.name,
                    "type": source.type,
                    "ip": source.ip,
                    "port": source.port,
                    "protocol": source.protocol,
                    "notifications": source.notifications
                })
                return fallback_sources[user_tenant][i]
        
        raise HTTPException(status_code=404, detail="Source not found")

@app.delete("/api/sources/{source_id}")
def delete_source(source_id: int, current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database delete
        db_source = db.query(SourceModel).filter(
            SourceModel.id == source_id,
            SourceModel.tenant_id == user_tenant
        ).first()
        
        if not db_source:
            raise HTTPException(status_code=404, detail="Source not found")
        
        db.delete(db_source)
        db.commit()
        
        return {"message": "Source deleted successfully"}
    else:
        # Fallback delete
        tenant_sources = fallback_sources.get(user_tenant, [])
        for i, s in enumerate(tenant_sources):
            if s["id"] == source_id:
                fallback_sources[user_tenant].pop(i)
                return {"message": "Source deleted successfully"}
        
        raise HTTPException(status_code=404, detail="Source not found")

@app.get("/api/notifications")
def get_notifications(current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database notifications
        notifications = db.query(NotificationModel).filter(
            NotificationModel.tenant_id == user_tenant
        ).order_by(NotificationModel.created_at.desc()).all()
        
        return [{
            "id": notif.id,
            "message": notif.message,
            "timestamp": notif.created_at.isoformat() if notif.created_at else None,
            "tenant": notif.tenant_id,
            "severity": notif.severity,
            "isRead": notif.is_read,
            "metadata": notif.meta_data
        } for notif in notifications]
    else:
        # Fallback notifications
        return fallback_notifications.get(user_tenant, [])

@app.get("/api/reports")
def get_reports(current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database reports
        reports = db.query(ReportModel).filter(
            ReportModel.tenant_id == user_tenant
        ).order_by(ReportModel.created_at.desc()).all()
        
        return [{
            "id": report.id,
            "title": report.title,
            "summary": report.summary,
            "tenant": report.tenant_id,
            "date": report.created_at.date().isoformat() if report.created_at else None,
            "type": report.report_type,
            "generatedBy": report.generated_by,
            "data": report.data
        } for report in reports]
    else:
        # Fallback reports
        return [
            {"id": 1, "title": "Security Summary Report", "summary": "Weekly security overview", "tenant": user_tenant, "date": datetime.now().date().isoformat(), "type": "security", "generatedBy": "system", "data": {"total_events": 1250}},
            {"id": 2, "title": "Threat Analysis Report", "summary": "Analysis of recent security threats", "tenant": user_tenant, "date": datetime.now().date().isoformat(), "type": "threat", "generatedBy": "admin", "data": {"threats_detected": 8}}
        ]

@app.patch("/api/notifications/{notification_id}/read")
def mark_notification_as_read(notification_id: int, current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database notification update
        notification = db.query(NotificationModel).filter(
            NotificationModel.id == notification_id,
            NotificationModel.tenant_id == user_tenant
        ).first()
        
        if notification:
            notification.is_read = True
            db.commit()
            return {"message": "Notification marked as read"}
        else:
            raise HTTPException(status_code=404, detail="Notification not found")
    else:
        # Fallback - update in-memory data
        tenant_notifications = fallback_notifications.get(user_tenant, [])
        for notification in tenant_notifications:
            if notification["id"] == notification_id:
                notification["isRead"] = True
                return {"message": "Notification marked as read"}
        
        raise HTTPException(status_code=404, detail="Notification not found")

@app.patch("/api/notifications/read-all")
def mark_all_notifications_as_read(current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database - mark all notifications as read
        notifications = db.query(NotificationModel).filter(
            NotificationModel.tenant_id == user_tenant,
            NotificationModel.is_read == False
        ).all()
        
        for notification in notifications:
            notification.is_read = True
        
        db.commit()
        return {"message": f"Marked {len(notifications)} notifications as read"}
    else:
        # Fallback - update in-memory data
        tenant_notifications = fallback_notifications.get(user_tenant, [])
        count = 0
        for notification in tenant_notifications:
            if not notification.get("isRead", False):
                notification["isRead"] = True
                count += 1
        
        return {"message": f"Marked {count} notifications as read"}

@app.post("/api/reports/generate")
def generate_report(report_type: str = "security", current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    # Generate report based on type
    if report_type == "security":
        title = "Security Summary Report"
        summary = "Automated security overview and threat analysis"
        data = {"total_events": 1250, "threats_detected": 3, "incidents_resolved": 2}
    elif report_type == "threat":
        title = "Threat Analysis Report"
        summary = "Analysis of recent security threats and vulnerabilities"
        data = {"threats_detected": 8, "high_risk": 2, "medium_risk": 4, "low_risk": 2}
    elif report_type == "performance":
        title = "Performance Metrics Report"
        summary = "System performance and resource utilization analysis"
        data = {"avg_response_time": "45ms", "uptime": "99.9%", "cpu_usage": "23%"}
    else:
        title = "Compliance Report"
        summary = "Compliance and audit findings"
        data = {"compliance_score": "95%", "audit_items": 12, "passed_checks": 11}
    
    if DATABASE_AVAILABLE and db:
        # Create report in database
        new_report = ReportModel(
            title=title,
            summary=summary,
            tenant_id=user_tenant,
            report_type=report_type,
            generated_by=current["name"],
            data=data
        )
        db.add(new_report)
        db.commit()
        db.refresh(new_report)
        
        return {
            "id": new_report.id,
            "title": new_report.title,
            "summary": new_report.summary,
            "tenant": new_report.tenant_id,
            "date": new_report.created_at.date().isoformat() if new_report.created_at else None,
            "type": new_report.report_type,
            "generatedBy": new_report.generated_by,
            "data": new_report.data
        }
    else:
        # Fallback - return generated report
        report_id = len(fallback_reports.get(user_tenant, [])) + 1
        return {
            "id": report_id,
            "title": title,
            "summary": summary,
            "tenant": user_tenant,
            "date": datetime.now().date().isoformat(),
            "type": report_type,
            "generatedBy": current["name"],
            "data": data
        }

# Admin endpoints
@app.get("/api/admin/tenants")
def get_all_tenants(current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database tenants - filter by access
        if current["role"] == "superadmin":
            tenants = db.query(TenantModel).all()
        else:
            tenants = db.query(TenantModel).filter(TenantModel.id == current["tenantId"]).all()
        
        return [{
            "id": tenant.id,
            "name": tenant.name,
            "userCount": tenant.user_count,
            "sourcesCount": tenant.sources_count,
            "status": tenant.status,
            "createdAt": tenant.created_at.isoformat() if tenant.created_at else None
        } for tenant in tenants]
    else:
        # Fallback tenants - filter by access
        if current["role"] == "superadmin":
            tenant_ids = set(user["tenantId"] for user in fallback_users.values())
        else:
            tenant_ids = {current["tenantId"]}
        
        tenants = {}
        for user in fallback_users.values():
            tenant_id = user["tenantId"]
            if tenant_id in tenant_ids:
                if tenant_id not in tenants:
                    tenants[tenant_id] = {
                        "id": tenant_id,
                        "name": tenant_id.replace("-", " ").title(),
                        "userCount": 0,
                        "sourcesCount": len(fallback_sources.get(tenant_id, [])),
                        "status": "active",
                        "createdAt": datetime.now().isoformat()
                    }
                tenants[tenant_id]["userCount"] += 1
        
        return list(tenants.values())

@app.post("/api/admin/tenants")
def create_tenant(tenant_data: dict, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database tenant creation
        existing_tenant = db.query(TenantModel).filter(TenantModel.id == tenant_data["id"]).first()
        if existing_tenant:
            raise HTTPException(status_code=400, detail="Tenant ID already exists")
        
        new_tenant = TenantModel(
            id=tenant_data["id"],
            name=tenant_data["name"],
            description=tenant_data.get("description", ""),
            status=tenant_data.get("status", "active")
        )
        db.add(new_tenant)
        db.commit()
        db.refresh(new_tenant)
        
        return {
            "id": new_tenant.id,
            "name": new_tenant.name,
            "description": new_tenant.description,
            "status": new_tenant.status
        }
    else:
        # Fallback tenant creation
        tenant_id = tenant_data["id"]
        if any(user["tenantId"] == tenant_id for user in fallback_users.values()):
            raise HTTPException(status_code=400, detail="Tenant ID already exists")
        
        # Initialize empty sources for new tenant
        fallback_sources[tenant_id] = []
        
        return {
            "id": tenant_id,
            "name": tenant_data["name"],
            "description": tenant_data.get("description", ""),
            "status": tenant_data.get("status", "active")
        }

@app.put("/api/admin/tenants/{tenant_id}")
def update_tenant(tenant_id: str, tenant_data: dict, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if admin is trying to update different tenant
    if current["role"] == "admin" and tenant_id != current["tenantId"]:
        raise HTTPException(status_code=403, detail="You can only update your own tenant")
    
    if DATABASE_AVAILABLE and db:
        # Database tenant update
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        tenant.name = tenant_data["name"]
        tenant.description = tenant_data.get("description", tenant.description)
        tenant.status = tenant_data.get("status", tenant.status)
        
        db.commit()
        db.refresh(tenant)
        
        return {
            "id": tenant.id,
            "name": tenant.name,
            "description": tenant.description,
            "status": tenant.status
        }
    else:
        # Fallback tenant update
        if not any(user["tenantId"] == tenant_id for user in fallback_users.values()):
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        # Update tenant name in user data
        for user in fallback_users.values():
            if user["tenantId"] == tenant_id:
                user["tenantName"] = tenant_data["name"]
        
        return {
            "id": tenant_id,
            "name": tenant_data["name"],
            "description": tenant_data.get("description", ""),
            "status": tenant_data.get("status", "active")
        }

@app.delete("/api/admin/tenants/{tenant_id}")
def delete_tenant(tenant_id: str, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database tenant deletion
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        # Delete associated users and sources
        db.query(UserModel).filter(UserModel.tenant_id == tenant_id).delete()
        db.query(SourceModel).filter(SourceModel.tenant_id == tenant_id).delete()
        
        db.delete(tenant)
        db.commit()
        
        return {"message": "Tenant deleted successfully"}
    else:
        # Fallback tenant deletion
        if not any(user["tenantId"] == tenant_id for user in fallback_users.values()):
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        # Remove users and sources for this tenant
        users_to_remove = [email for email, user in fallback_users.items() if user["tenantId"] == tenant_id]
        for email in users_to_remove:
            del fallback_users[email]
        
        if tenant_id in fallback_sources:
            del fallback_sources[tenant_id]
        
        return {"message": "Tenant deleted successfully"}

@app.patch("/api/admin/tenants/{tenant_id}/status")
def update_tenant_status(tenant_id: str, status_data: dict, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    new_status = status_data.get("status")
    if new_status not in ["active", "suspended"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    # Check if admin is trying to update different tenant
    if current["role"] == "admin" and tenant_id != current["tenantId"]:
        raise HTTPException(status_code=403, detail="You can only update your own tenant")
    
    if DATABASE_AVAILABLE and db:
        # Database tenant status update
        tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        tenant.status = new_status
        db.commit()
        
        return {"message": f"Tenant status updated to {new_status}"}
    else:
        # Fallback tenant status update
        if not any(user["tenantId"] == tenant_id for user in fallback_users.values()):
            raise HTTPException(status_code=404, detail="Tenant not found")
        
        # Update status in user data (this is a simplified approach)
        for user in fallback_users.values():
            if user["tenantId"] == tenant_id:
                user["tenantStatus"] = new_status
        
        return {"message": f"Tenant status updated to {new_status}"}

@app.get("/api/admin/users")
def get_all_users(current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database users - filter by tenant access
        if current["role"] == "superadmin":
            users = db.query(UserModel).all()
        else:
            users = db.query(UserModel).filter(UserModel.tenant_id == current["tenantId"]).all()
        
        return [{
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "tenantId": user.tenant_id,
            "role": user.role,
            "isActive": user.is_active
        } for user in users]
    else:
        # Fallback users - filter by tenant access
        if current["role"] == "superadmin":
            user_list = fallback_users.values()
        else:
            user_list = [user for user in fallback_users.values() if user["tenantId"] == current["tenantId"]]
        
        return [
            {
                "id": user["email"],
                "name": user["name"],
                "email": user["email"],
                "tenantId": user["tenantId"],
                "role": user["role"],
                "isActive": user.get("is_active", True)
            }
            for user in user_list
        ]

# Dashboard stats endpoint
@app.post("/api/admin/users")
def create_user(user_data: dict, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Validate tenant access
    if current["role"] == "admin" and user_data.get("tenantId") != current["tenantId"]:
        raise HTTPException(status_code=403, detail="You can only create users for your own tenant")
    
    if DATABASE_AVAILABLE and db:
        # Database user creation
        existing_user = db.query(UserModel).filter(UserModel.email == user_data["email"]).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        new_user = UserModel(
            id=user_data["email"],
            email=user_data["email"],
            password=user_data["password"],
            name=user_data["name"],
            tenant_id=user_data["tenantId"],
            role=user_data["role"],
            is_active=user_data.get("status", "active") == "active"
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        return {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
            "tenantId": new_user.tenant_id,
            "role": new_user.role,
            "isActive": new_user.is_active
        }
    else:
        # Fallback user creation
        if user_data["email"] in fallback_users:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        fallback_users[user_data["email"]] = {
            "email": user_data["email"],
            "password": user_data["password"],
            "name": user_data["name"],
            "tenantId": user_data["tenantId"],
            "role": user_data["role"],
            "tenants": [user_data["tenantId"]],
            "is_active": user_data.get("status", "active") == "active"
        }
        
        return {
            "id": user_data["email"],
            "name": user_data["name"],
            "email": user_data["email"],
            "tenantId": user_data["tenantId"],
            "role": user_data["role"],
            "isActive": user_data.get("status", "active") == "active"
        }

@app.put("/api/admin/users/{user_id}")
def update_user(user_id: str, user_data: dict, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Validate tenant access
    if current["role"] == "admin" and user_data.get("tenantId") != current["tenantId"]:
        raise HTTPException(status_code=403, detail="You can only update users in your own tenant")
    
    if DATABASE_AVAILABLE and db:
        # Database user update
        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if admin is trying to update user from different tenant
        if current["role"] == "admin" and user.tenant_id != current["tenantId"]:
            raise HTTPException(status_code=403, detail="You can only update users in your own tenant")
        
        user.name = user_data["name"]
        user.email = user_data["email"]
        user.tenant_id = user_data["tenantId"]
        user.role = user_data["role"]
        user.is_active = user_data.get("status", "active") == "active"
        
        if user_data.get("password"):
            user.password = user_data["password"]
        
        db.commit()
        db.refresh(user)
        
        return {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "tenantId": user.tenant_id,
            "role": user.role,
            "isActive": user.is_active
        }
    else:
        # Fallback user update
        if user_id not in fallback_users:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if admin is trying to update user from different tenant
        if current["role"] == "admin" and fallback_users[user_id]["tenantId"] != current["tenantId"]:
            raise HTTPException(status_code=403, detail="You can only update users in your own tenant")
        
        fallback_users[user_id].update({
            "name": user_data["name"],
            "email": user_data["email"],
            "tenantId": user_data["tenantId"],
            "role": user_data["role"],
            "is_active": user_data.get("status", "active") == "active"
        })
        
        if user_data.get("password"):
            fallback_users[user_id]["password"] = user_data["password"]
        
        return {
            "id": user_id,
            "name": user_data["name"],
            "email": user_data["email"],
            "tenantId": user_data["tenantId"],
            "role": user_data["role"],
            "isActive": user_data.get("status", "active") == "active"
        }

@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: str, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database user deletion
        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if admin is trying to delete user from different tenant
        if current["role"] == "admin" and user.tenant_id != current["tenantId"]:
            raise HTTPException(status_code=403, detail="You can only delete users in your own tenant")
        
        # Prevent admin from deleting themselves
        if user.email == current["email"]:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        db.delete(user)
        db.commit()
        
        return {"message": "User deleted successfully"}
    else:
        # Fallback user deletion
        if user_id not in fallback_users:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if admin is trying to delete user from different tenant
        if current["role"] == "admin" and fallback_users[user_id]["tenantId"] != current["tenantId"]:
            raise HTTPException(status_code=403, detail="You can only delete users in your own tenant")
        
        # Prevent admin from deleting themselves
        if fallback_users[user_id]["email"] == current["email"]:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        del fallback_users[user_id]
        
        return {"message": "User deleted successfully"}

@app.patch("/api/admin/users/{user_id}/status")
def update_user_status(user_id: str, status_data: dict, current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    new_status = status_data.get("status")
    if new_status not in ["active", "suspended"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    if DATABASE_AVAILABLE and db:
        # Database user status update
        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if admin is trying to update user from different tenant
        if current["role"] == "admin" and user.tenant_id != current["tenantId"]:
            raise HTTPException(status_code=403, detail="You can only update users in your own tenant")
        
        user.is_active = new_status == "active"
        db.commit()
        
        return {"message": f"User status updated to {new_status}"}
    else:
        # Fallback user status update
        if user_id not in fallback_users:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if admin is trying to update user from different tenant
        if current["role"] == "admin" and fallback_users[user_id]["tenantId"] != current["tenantId"]:
            raise HTTPException(status_code=403, detail="You can only update users in your own tenant")
        
        fallback_users[user_id]["is_active"] = new_status == "active"
        
        return {"message": f"User status updated to {new_status}"}

# Tenant SIEM Configuration endpoints
@app.get("/api/tenant/config")
def get_tenant_config(
    current=Depends(get_current_user),
    db=Depends(get_db),
    protocol: str = Query(None, description="Protocol override (udp, tcp, tls)"),
    syslog_format: str = Query(None, description="Syslog format override (rfc3164, rfc5424, cisco)")
):
    """Get SIEM configuration for the current tenant (same IP/port for all tenants)"""
    user_tenant = current["tenantId"]
    print(f"Getting SIEM config for tenant: {user_tenant}")
    # Always use config manager for SIEM config
    siem_config = config.generate_tenant_siem_config(user_tenant, protocol=protocol, syslog_format=syslog_format)
    return {
        "id": 1,
        "tenant_id": user_tenant,
        "last_configured": datetime.now().isoformat(),
        "created_at": datetime.now().isoformat(),
        **siem_config
    }

@app.put("/api/tenant/config")
def update_tenant_config(config: TenantConfig, current=Depends(get_current_user), db = Depends(get_db)):
    """Update SIEM configuration for the current tenant"""
    user_tenant = current["tenantId"]
    print(f"Updating SIEM config for tenant: {user_tenant}")
    
    if DATABASE_AVAILABLE and db:
        # Database config update
        existing_config = db.query(TenantConfigModel).filter(TenantConfigModel.tenant_id == user_tenant).first()
        
        if existing_config:
            # Update existing config
            existing_config.siem_server_ip = config.siem_server_ip
            existing_config.siem_server_port = config.siem_server_port
            existing_config.siem_protocol = config.siem_protocol
            existing_config.syslog_format = config.syslog_format
            existing_config.facility = config.facility
            existing_config.severity = config.severity
            existing_config.enabled = config.enabled
            existing_config.setup_instructions = config.setup_instructions
            existing_config.last_configured = datetime.utcnow()
        else:
            # Create new config
            existing_config = TenantConfigModel(
                tenant_id=user_tenant,
                siem_server_ip=config.siem_server_ip,
                siem_server_port=config.siem_server_port,
                siem_protocol=config.siem_protocol,
                syslog_format=config.syslog_format,
                facility=config.facility,
                severity=config.severity,
                enabled=config.enabled,
                setup_instructions=config.setup_instructions,
                last_configured=datetime.utcnow()
            )
            db.add(existing_config)
        
        db.commit()
        db.refresh(existing_config)
        
        return {
            "id": existing_config.id,
            "tenant_id": existing_config.tenant_id,
            "siem_server_ip": existing_config.siem_server_ip,
            "siem_server_port": existing_config.siem_server_port,
            "siem_protocol": existing_config.siem_protocol,
            "syslog_format": existing_config.syslog_format,
            "facility": existing_config.facility,
            "severity": existing_config.severity,
            "enabled": existing_config.enabled,
            "setup_instructions": existing_config.setup_instructions,
            "last_configured": existing_config.last_configured.isoformat() if existing_config.last_configured else None,
            "created_at": existing_config.created_at.isoformat() if existing_config.created_at else None
        }
    else:
        # Fallback config update (in-memory only)
        return {
            "id": 1,
            "tenant_id": user_tenant,
            "siem_server_ip": config.siem_server_ip,
            "siem_server_port": config.siem_server_port,
            "siem_protocol": config.siem_protocol,
            "syslog_format": config.syslog_format,
            "facility": config.facility,
            "severity": config.severity,
            "enabled": config.enabled,
            "setup_instructions": config.setup_instructions,
            "last_configured": datetime.now().isoformat(),
            "created_at": datetime.now().isoformat()
        }

@app.get("/api/tenant/setup-guide")
def get_setup_guide(current=Depends(get_current_user), db = Depends(get_db)):
    """Get comprehensive setup guide for the current tenant"""
    user_tenant = current["tenantId"]
    
    # Get tenant config
    config_response = get_tenant_config(current, db)
    
    setup_guide = {
        "tenant_id": user_tenant,
        "siem_config": config_response,
        "setup_steps": [
            {
                "step": 1,
                "title": "Configure Syslog on Your Devices",
                "description": "Configure your network devices, servers, and applications to send syslog messages to the SIEM server.",
                "examples": {
                    "cisco_ios": f"logging {config_response['siem_server_ip']}",
                    "cisco_asa": f"logging host inside {config_response['siem_server_ip']} {config_response['siem_protocol']}",
                    "linux_rsyslog": f"*.* @{config_response['siem_server_ip']}:{config_response['siem_server_port']}",
                    "windows_eventlog": "Use Windows Event Forwarding or third-party tools",
                    "firewall": f"Configure syslog output to {config_response['siem_server_ip']}:{config_response['siem_server_port']}"
                }
            },
            {
                "step": 2,
                "title": "Verify Connectivity",
                "description": "Test that your devices can reach the SIEM server and send syslog messages.",
                "commands": [
                    f"telnet {config_response['siem_server_ip']} {config_response['siem_server_port']}",
                    f"nc -u {config_response['siem_server_ip']} {config_response['siem_server_port']}",
                    f"Test syslog message: echo '<134>Jan 15 10:30:00 testhost testapp: Test message' | nc -u {config_response['siem_server_ip']} {config_response['siem_server_port']}"
                ]
            },
            {
                "step": 3,
                "title": "Monitor Dashboard",
                "description": "Check the SIEM dashboard to verify that events are being received and processed.",
                "actions": [
                    "Log into the SIEM dashboard",
                    "Check the Sources page for active connections",
                    "Monitor the Notifications page for alerts",
                    "Review the Dashboard for real-time statistics"
                ]
            },
            {
                "step": 4,
                "title": "Configure Alerts",
                "description": "Set up notification preferences and alert thresholds for your environment.",
                "settings": [
                    "Configure email notifications",
                    "Set up alert severity levels",
                    "Define custom alert rules",
                    "Configure notification schedules"
                ]
            }
        ],
        "supported_formats": [
            {
                "name": "RFC 3164",
                "description": "Traditional syslog format",
                "example": "<134>Jan 15 10:30:00 testhost testapp: Test message"
            },
            {
                "name": "RFC 5424",
                "description": "Modern syslog format with structured data",
                "example": "<134>1 2024-01-15T10:30:00.000Z testhost testapp 12345 - - Test message"
            },
            {
                "name": "Cisco",
                "description": "Cisco-specific syslog format",
                "example": "%ASA-6-106100: access-list ACL-INFRA-01 permitted tcp inside/192.168.1.100(12345) -> outside/203.0.113.1(80) hit-cnt 1 first hit [0x12345678, 0x0]"
            }
        ],
        "troubleshooting": [
            {
                "issue": "No events received",
                "solutions": [
                    "Check network connectivity to SIEM server",
                    "Verify syslog configuration on source devices",
                    "Check firewall rules and port access",
                    "Test with manual syslog message"
                ]
            },
            {
                "issue": "Events not appearing in dashboard",
                "solutions": [
                    "Check tenant configuration",
                    "Verify source IP mapping to tenant",
                    "Check processing service status",
                    "Review system logs"
                ]
            },
            {
                "issue": "High latency in event processing",
                "solutions": [
                    "Check network bandwidth",
                    "Verify syslog server performance",
                    "Review processing service configuration",
                    "Consider load balancing for high volume"
                ]
            }
        ]
    }
    
    return setup_guide

@app.get("/api/dashboard/stats")
def get_dashboard_stats(current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    print(f"Getting dashboard stats for tenant: {user_tenant}")
    
    if DATABASE_AVAILABLE and db:
        # Database stats
        try:
            sources_count = db.query(SourceModel).filter(SourceModel.tenant_id == user_tenant).count()
            active_sources = db.query(SourceModel).filter(
                SourceModel.tenant_id == user_tenant,
                SourceModel.status == 'active'
            ).count()
            
            unread_alerts = db.query(NotificationModel).filter(
                NotificationModel.tenant_id == user_tenant,
                NotificationModel.is_read == False,
                NotificationModel.severity.in_(['critical', 'warning'])
            ).count()
            
            reports = db.query(ReportModel).filter(ReportModel.tenant_id == user_tenant).all()
            total_events = sum(report.data.get('total_events', 0) if report.data else 0 for report in reports)
            
            return {
                "totalSources": sources_count,
                "activeSources": active_sources,
                "alerts": unread_alerts,
                "totalEvents": total_events,
                "uptime": "99.9%" if active_sources > 0 else "0%"
            }
        except Exception as e:
            print(f"Error getting database stats: {e}")
            # Fall through to fallback
    
    # Fallback stats
    tenant_sources = fallback_sources.get(user_tenant, [])
    active_sources = len([s for s in tenant_sources if s.get('status') == 'active'])
    
    return {
        "totalSources": len(tenant_sources),
        "activeSources": active_sources,
        "alerts": 0,  # New tenants start with zero alerts
        "totalEvents": 0,  # New tenants start with zero events
        "uptime": "99.9%" if active_sources > 0 else "0%"
    }

# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "BITS-SIEM API",
        "version": "1.0.0",
        "database": "PostgreSQL" if DATABASE_AVAILABLE else "In-Memory Fallback",
        "timestamp": datetime.now().isoformat()
    }

# Database status endpoint
@app.get("/api/status")
def get_status():
    return {
        "database_available": DATABASE_AVAILABLE,
        "storage_type": "PostgreSQL" if DATABASE_AVAILABLE else "In-Memory",
        "persistent": DATABASE_AVAILABLE,
        "shared_across_services": DATABASE_AVAILABLE
    }

# WebSocket endpoint
@app.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({
                "type": "notification",
                "data": {
                    "message": "System status update",
                    "timestamp": datetime.now().isoformat(),
                    "severity": "info"
                }
            })
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        print("WebSocket disconnected")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
import time
import asyncio
from datetime import datetime, timedelta

# Try to import database functionality
try:
    from database_working import (
        get_db, init_db, 
        Tenant as TenantModel, 
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

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

app = FastAPI(title="BITS-SIEM API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Fallback in-memory data (used when database is not available)
fallback_users = {
    "admin@acme.com": {
        "email": "admin@acme.com",
        "password": "admin123",
        "name": "Acme Admin",
        "tenantId": "acme-corp",
        "role": "admin",
        "tenants": ["acme-corp"],
        "is_active": True
    },
    "user@acme.com": {
        "email": "user@acme.com",
        "password": "user123",
        "name": "Acme User",
        "tenantId": "acme-corp",
        "role": "user",
        "tenants": ["acme-corp"],
        "is_active": True
    },
    "admin@beta.com": {
        "email": "admin@beta.com",
        "password": "admin123",
        "name": "Beta Admin",
        "tenantId": "beta-industries",
        "role": "admin",
        "tenants": ["beta-industries"],
        "is_active": True
    },
    "aspundir@cisco.com": {
        "email": "aspundir@cisco.com",
        "password": "password123",
        "name": "Aspundir Singh",
        "tenantId": "cisco-systems",
        "role": "admin",
        "tenants": ["cisco-systems"],
        "is_active": True
    },
    "admin@demo.com": {
        "email": "admin@demo.com",
        "password": "demo123",
        "name": "Demo Admin",
        "tenantId": "demo-org",
        "role": "admin",
        "tenants": ["demo-org"],
        "is_active": True
    },
    "user@demo.com": {
        "email": "user@demo.com",
        "password": "demo123",
        "name": "Demo User",
        "tenantId": "demo-org",
        "role": "user",
        "tenants": ["demo-org"],
        "is_active": True
    }
}

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
        else:
            print("⚠️  Database initialization failed, using fallback mode")
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
    if DATABASE_AVAILABLE and db:
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
        
    else:
        # Fallback registration
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
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(login_data: LoginRequest, db = Depends(get_db)):
    if DATABASE_AVAILABLE and db:
        # Database login
        user = db.query(UserModel).filter(UserModel.email == login_data.email).first()
        
        if not user or user.password != login_data.password or not user.is_active:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        token = create_jwt(user)
        return {
            "token": token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "tenantId": user.tenant_id,
                "role": user.role,
                "tenants": user.tenants_access or [user.tenant_id]
            }
        }
    else:
        # Fallback login
        user_data = fallback_users.get(login_data.email)
        
        if not user_data or user_data["password"] != login_data.password:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        if not user_data.get("is_active", True):
            raise HTTPException(status_code=401, detail="Account is inactive")
        
        token = create_jwt(user_data)
        return {
            "token": token,
            "user": {
                "id": user_data["email"],
                "name": user_data["name"],
                "email": user_data["email"],
                "tenantId": user_data["tenantId"],
                "role": user_data["role"],
                "tenants": user_data["tenants"]
            }
        }

# SIEM Data endpoints
@app.get("/api/sources")
def get_sources(current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
        # Database sources
        sources = db.query(SourceModel).filter(SourceModel.tenant_id == user_tenant).all()
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
        return fallback_sources.get(user_tenant, [])

@app.post("/api/sources")
def add_source(source: Source, current=Depends(get_current_user), db = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    if DATABASE_AVAILABLE and db:
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
        if user_tenant not in fallback_sources:
            fallback_sources[user_tenant] = []
        
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
            "metadata": notif.metadata
        } for notif in notifications]
    else:
        # Fallback notifications
        return [
            {"id": 1, "message": "High CPU usage detected on Web Server", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "warning", "isRead": False, "metadata": {"cpu_usage": "85%"}},
            {"id": 2, "message": "Suspicious login attempt blocked", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "critical", "isRead": False, "metadata": {"ip": "192.168.1.50"}},
            {"id": 3, "message": "System backup completed successfully", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "info", "isRead": True, "metadata": {"backup_size": "2.3GB"}}
        ]

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

# Admin endpoints
@app.get("/api/admin/tenants")
def get_all_tenants(current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database tenants
        tenants = db.query(TenantModel).all()
        return [{
            "id": tenant.id,
            "name": tenant.name,
            "userCount": tenant.user_count,
            "sourcesCount": tenant.sources_count,
            "status": tenant.status
        } for tenant in tenants]
    else:
        # Fallback tenants
        tenants = {}
        for user in fallback_users.values():
            tenant_id = user["tenantId"]
            if tenant_id not in tenants:
                tenants[tenant_id] = {
                    "id": tenant_id,
                    "name": tenant_id.replace("-", " ").title(),
                    "userCount": 0,
                    "sourcesCount": len(fallback_sources.get(tenant_id, [])),
                    "status": "active"
                }
            tenants[tenant_id]["userCount"] += 1
        
        return list(tenants.values())

@app.get("/api/admin/users")
def get_all_users(current=Depends(get_current_user), db = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if DATABASE_AVAILABLE and db:
        # Database users
        users = db.query(UserModel).all()
        return [{
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "tenantId": user.tenant_id,
            "role": user.role,
            "isActive": user.is_active
        } for user in users]
    else:
        # Fallback users
        return [
            {
                "id": user["email"],
                "name": user["name"],
                "email": user["email"],
                "tenantId": user["tenantId"],
                "role": user["role"],
                "isActive": user.get("is_active", True)
            }
            for user in fallback_users.values()
        ]

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

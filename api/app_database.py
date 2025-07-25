from fastapi import FastAPI, WebSocket, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import time
import asyncio
from datetime import datetime, timedelta
# Try to import database functionality, fall back to simple version if failed
try:
    from sqlalchemy.orm import Session
    from database import (
        get_db, init_db, 
        Tenant as TenantModel, 
        User as UserModel, 
        Source as SourceModel,
        Notification as NotificationModel,
        Report as ReportModel,
        SQLALCHEMY_AVAILABLE
    )
    if not SQLALCHEMY_AVAILABLE:
        raise ImportError("SQLAlchemy not available")
except (ImportError, AttributeError) as e:
    print(f"Using simple database fallback: {e}")
    from database_simple import (
        get_db, init_db,
        TenantModel, UserModel, SourceModel,
        NotificationModel, ReportModel
    )
    SQLALCHEMY_AVAILABLE = False
    
    # Mock Session class for compatibility
    class Session:
        pass

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

app = FastAPI(title="BITS-SIEM API", description="Multi-tenant SIEM API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Fallback in-memory data if database fails
fallback_users = {
    "admin@acme.com": {
        "email": "admin@acme.com",
        "password": "admin123",
        "name": "Acme Admin",
        "tenantId": "acme-corp",
        "role": "admin",
        "tenants": ["acme-corp"]
    },
    "user@acme.com": {
        "email": "user@acme.com",
        "password": "user123",
        "name": "Acme User",
        "tenantId": "acme-corp",
        "role": "user",
        "tenants": ["acme-corp"]
    },
    "admin@beta.com": {
        "email": "admin@beta.com",
        "password": "admin123",
        "name": "Beta Admin",
        "tenantId": "beta-industries",
        "role": "admin",
        "tenants": ["beta-industries"]
    }
}

use_database = SQLALCHEMY_AVAILABLE

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    global use_database
    try:
        print("Initializing database...")
        init_db()
        print("Database initialization completed")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        print("Falling back to in-memory storage")
        use_database = False

# Pydantic Models
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    tenant: str
    role: str = "user"

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    tenantId: str
    role: str
    tenants: Optional[List[str]] = None

class TenantResponse(BaseModel):
    id: str
    name: str

class Source(BaseModel):
    name: str
    type: str
    ip: str
    port: int
    protocol: str
    notifications: dict = None

class Notification(BaseModel):
    id: int
    message: str
    timestamp: str
    tenant: str

class Report(BaseModel):
    id: int
    title: str
    summary: str
    tenant: str

# Helper functions
def create_jwt(user: UserModel):
    payload = {
        "email": user.email,
        "tenantId": user.tenant_id,
        "role": user.role,
        "name": user.name,
        "user_id": user.id
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db) if use_database else None):
    try:
        print(f"Validating token: {token[:20]}...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        print(f"Token payload email: {email}")
        
        if email is None:
            print("No email in token payload")
            raise HTTPException(status_code=401, detail="Invalid token")
        
        if use_database and db:
            # Verify user still exists in database
            user = db.query(UserModel).filter(UserModel.email == email).first()
            if not user:
                print(f"User not found in database: {email}")
                raise HTTPException(status_code=401, detail="User not found")
            
            if not user.is_active:
                print(f"User inactive: {email}")
                raise HTTPException(status_code=401, detail="User inactive")
            
            print(f"Database user validation successful: {user.email}, tenant: {user.tenant_id}")
            return {
                "email": user.email,
                "tenantId": user.tenant_id,
                "role": user.role,
                "name": user.name,
                "user_id": user.id
            }
        else:
            # Fallback validation using token payload
            print("Using fallback token validation")
            user_data = fallback_users.get(email)
            if not user_data:
                print(f"User not found in fallback data: {email}")
                raise HTTPException(status_code=401, detail="User not found")
            
            print(f"Fallback user validation successful: {email}, tenant: {payload.get('tenantId')}")
            return {
                "email": payload.get("email"),
                "tenantId": payload.get("tenantId"),
                "role": payload.get("role"),
                "name": payload.get("name"),
                "user_id": payload.get("user_id")
            }
    except JWTError as e:
        print(f"JWT decode error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in get_current_user: {e}")
        raise HTTPException(status_code=500, detail="Authentication error")

# Authentication endpoints
@app.post("/api/auth/register")
def register(user_data: RegisterRequest, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create tenant if it doesn't exist
    tenant_id = user_data.tenant.lower().replace(" ", "-")
    tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
    
    if not tenant:
        tenant = TenantModel(
            id=tenant_id,
            name=user_data.tenant,
            status="active",
            user_count=0
        )
        db.add(tenant)
        db.flush()  # Get the tenant ID
    
    # Create user
    new_user = UserModel(
        email=user_data.email,
        password=user_data.password,  # In production, hash this password
        name=user_data.name,
        tenant_id=tenant_id,
        role=user_data.role,
        tenants_access=[tenant_id]
    )
    db.add(new_user)
    
    # Update tenant user count
    tenant.user_count = db.query(UserModel).filter(UserModel.tenant_id == tenant_id).count() + 1
    
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(login_data: LoginRequest, db: Session = Depends(get_db) if use_database else None):
    try:
        print(f"Login attempt for: {login_data.email}")
        
        if use_database and db:
            # Find user in database
            user = db.query(UserModel).filter(UserModel.email == login_data.email).first()
            print(f"Database user found: {user is not None}")
            
            if not user:
                print(f"No user found in database: {login_data.email}")
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            if user.password != login_data.password:
                print(f"Password mismatch for user: {login_data.email}")
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            if not user.is_active:
                print(f"User inactive: {login_data.email}")
                raise HTTPException(status_code=401, detail="Account is inactive")
            
            # Create token for database user
            token = create_jwt(user)
            print(f"Database login successful for: {user.email}, tenant: {user.tenant_id}")
            
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
            # Fallback to in-memory data
            print("Using fallback in-memory authentication")
            user_data = fallback_users.get(login_data.email)
            
            if not user_data or user_data["password"] != login_data.password:
                print(f"Fallback auth failed for: {login_data.email}")
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            # Create simple token for fallback user
            token_payload = {
                "email": user_data["email"],
                "tenantId": user_data["tenantId"],
                "role": user_data["role"],
                "name": user_data["name"],
                "user_id": user_data["email"]  # Use email as ID for fallback
            }
            token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
            print(f"Fallback login successful for: {user_data['email']}, tenant: {user_data['tenantId']}")
            
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
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Fallback sources data
fallback_sources = {
    "acme-corp": [
        {
            "id": 1,
            "name": "Web Server",
            "type": "web-server",
            "ip": "192.168.1.100",
            "port": 80,
            "protocol": "http",
            "status": "active",
            "lastActivity": datetime.now().isoformat(),
            "tenant": "acme-corp",
            "notifications": {
                "enabled": True,
                "emails": ["admin@acme.com", "security@acme.com"]
            }
        },
        {
            "id": 2,
            "name": "Database Server",
            "type": "database",
            "ip": "192.168.1.200",
            "port": 3306,
            "protocol": "tcp",
            "status": "active",
            "lastActivity": datetime.now().isoformat(),
            "tenant": "acme-corp",
            "notifications": {
                "enabled": True,
                "emails": ["dba@acme.com"]
            }
        }
    ],
    "beta-industries": [
        {
            "id": 3,
            "name": "Firewall",
            "type": "firewall",
            "ip": "10.0.1.1",
            "port": 514,
            "protocol": "udp",
            "status": "warning",
            "lastActivity": (datetime.now() - timedelta(hours=1)).isoformat(),
            "tenant": "beta-industries",
            "notifications": {
                "enabled": True,
                "emails": ["admin@beta.com"]
            }
        }
    ]
}

# SIEM Data endpoints
@app.get("/api/sources")
def get_sources(current=Depends(get_current_user), db: Session = Depends(get_db) if use_database else None):
    try:
        user_tenant = current["tenantId"]
        print(f"Getting sources for tenant: {user_tenant}")
        
        if use_database and db:
            sources = db.query(SourceModel).filter(SourceModel.tenant_id == user_tenant).all()
            print(f"Found {len(sources)} database sources")
            
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
            # Use fallback data
            print("Using fallback sources data")
            tenant_sources = fallback_sources.get(user_tenant, [])
            print(f"Found {len(tenant_sources)} fallback sources")
            return tenant_sources
    except Exception as e:
        print(f"Error getting sources: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving sources")

@app.post("/api/sources")
def add_source(source: Source, current=Depends(get_current_user), db: Session = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    # Create new source
    new_source = SourceModel(
        name=source.name,
        type=source.type,
        ip=source.ip,
        port=source.port,
        protocol=source.protocol,
        status="active",
        tenant_id=user_tenant,
        notifications=source.notifications or {"enabled": False, "emails": []}
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

@app.put("/api/sources/{source_id}")
def update_source(source_id: int, source: Source, current=Depends(get_current_user), db: Session = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    # Find source
    db_source = db.query(SourceModel).filter(
        SourceModel.id == source_id,
        SourceModel.tenant_id == user_tenant
    ).first()
    
    if not db_source:
        raise HTTPException(status_code=404, detail="Source not found")
    
    # Update source
    db_source.name = source.name
    db_source.type = source.type
    db_source.ip = source.ip
    db_source.port = source.port
    db_source.protocol = source.protocol
    db_source.notifications = source.notifications or {"enabled": False, "emails": []}
    
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

@app.delete("/api/sources/{source_id}")
def delete_source(source_id: int, current=Depends(get_current_user), db: Session = Depends(get_db)):
    user_tenant = current["tenantId"]
    
    # Find source
    db_source = db.query(SourceModel).filter(
        SourceModel.id == source_id,
        SourceModel.tenant_id == user_tenant
    ).first()
    
    if not db_source:
        raise HTTPException(status_code=404, detail="Source not found")
    
    db.delete(db_source)
    db.commit()
    
    return {"message": "Source deleted successfully"}

@app.get("/api/notifications")
def get_notifications(current=Depends(get_current_user), db: Session = Depends(get_db) if use_database else None):
    user_tenant = current["tenantId"]
    
    if use_database and db:
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
        fallback_notifications = [
            {"id": 1, "message": "High CPU usage detected on Web Server", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "warning", "isRead": False, "metadata": {"cpu_usage": "85%"}},
            {"id": 2, "message": "Suspicious login attempt blocked", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "critical", "isRead": False, "metadata": {"ip": "192.168.1.50"}},
            {"id": 3, "message": "System backup completed successfully", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "info", "isRead": True, "metadata": {"backup_size": "2.3GB"}}
        ]
        return fallback_notifications

@app.get("/api/reports")
def get_reports(current=Depends(get_current_user), db: Session = Depends(get_db) if use_database else None):
    user_tenant = current["tenantId"]
    
    if use_database and db:
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
        fallback_reports = [
            {"id": 1, "title": "Security Summary Report", "summary": "Weekly security overview", "tenant": user_tenant, "date": datetime.now().date().isoformat(), "type": "security", "generatedBy": "system", "data": {"total_events": 1250}},
            {"id": 2, "title": "Threat Analysis Report", "summary": "Analysis of recent security threats", "tenant": user_tenant, "date": datetime.now().date().isoformat(), "type": "threat", "generatedBy": "admin", "data": {"threats_detected": 8}}
        ]
        return fallback_reports

# Admin endpoints
@app.get("/api/admin/tenants")
def get_all_tenants(current=Depends(get_current_user), db: Session = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Super admin can see all tenants
    if current["role"] == "superadmin":
        tenants = db.query(TenantModel).all()
    else:
        # Regular admin can only see their own tenant
        tenants = db.query(TenantModel).filter(TenantModel.id == current["tenantId"]).all()
    
    return [{
        "id": tenant.id,
        "name": tenant.name,
        "status": tenant.status,
        "userCount": tenant.user_count,
        "description": tenant.description,
        "createdAt": tenant.created_at.isoformat() if tenant.created_at else None
    } for tenant in tenants]

@app.post("/api/admin/tenants")
def create_tenant(tenant_data: dict, current=Depends(get_current_user), db: Session = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    tenant_id = tenant_data["name"].lower().replace(" ", "-")
    
    # Check if tenant already exists
    existing_tenant = db.query(TenantModel).filter(TenantModel.id == tenant_id).first()
    if existing_tenant:
        raise HTTPException(status_code=400, detail="Tenant already exists")
    
    # Create new tenant
    new_tenant = TenantModel(
        id=tenant_id,
        name=tenant_data["name"],
        status="active",
        user_count=0,
        description=tenant_data.get("description", "")
    )
    
    db.add(new_tenant)
    db.commit()
    db.refresh(new_tenant)
    
    return {
        "id": new_tenant.id,
        "name": new_tenant.name,
        "status": new_tenant.status,
        "userCount": new_tenant.user_count,
        "description": new_tenant.description
    }

@app.get("/api/admin/users")
def get_all_users(tenantId: str = None, current=Depends(get_current_user), db: Session = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Build query based on permissions
    query = db.query(UserModel)
    
    if current["role"] == "superadmin":
        # Super admin can see all users
        if tenantId:
            query = query.filter(UserModel.tenant_id == tenantId)
    else:
        # Regular admin can only see users in their own tenant
        query = query.filter(UserModel.tenant_id == current["tenantId"])
    
    users = query.all()
    
    return [{
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "tenantId": user.tenant_id,
        "tenantName": user.tenant.name if user.tenant else user.tenant_id,
        "status": "active" if user.is_active else "inactive",
        "createdAt": user.created_at.isoformat() if user.created_at else None
    } for user in users]

@app.post("/api/admin/users")
def create_user(user_data: RegisterRequest, current=Depends(get_current_user), db: Session = Depends(get_db)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if user already exists
    existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Validate tenant access for regular admins
    if current["role"] == "admin" and user_data.tenant != current["tenantId"]:
        raise HTTPException(status_code=403, detail="Cannot create users for other tenants")
    
    # Create user
    new_user = UserModel(
        email=user_data.email,
        password=user_data.password,  # In production, hash this
        name=user_data.name,
        tenant_id=user_data.tenant,
        role=user_data.role,
        tenants_access=[user_data.tenant]
    )
    
    db.add(new_user)
    
    # Update tenant user count
    tenant = db.query(TenantModel).filter(TenantModel.id == user_data.tenant).first()
    if tenant:
        tenant.user_count += 1
    
    db.commit()
    
    return {"message": "User created successfully"}

# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "BITS-SIEM API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

# Test endpoint to check database
@app.get("/api/test/users")
def test_users(db: Session = Depends(get_db)):
    try:
        users = db.query(UserModel).all()
        return {
            "total_users": len(users),
            "users": [{
                "email": user.email,
                "name": user.name,
                "tenant_id": user.tenant_id,
                "role": user.role,
                "is_active": user.is_active
            } for user in users]
        }
    except Exception as e:
        return {"error": str(e)}

# WebSocket endpoint
@app.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    token = websocket.query_params.get("token")
    try:
        user = get_current_user(token)
        tenant = user["tenant"]
        while True:
            # Simulate sending a notification every 10 seconds
            await websocket.send_json({
                "id": int(time.time()),
                "message": f"Alert for tenant {tenant}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "tenant": tenant
            })
            await asyncio.sleep(10)
    except Exception as e:
        await websocket.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) 
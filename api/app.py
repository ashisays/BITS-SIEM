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

# In-memory stores for demo - Initialize with sample data
users = {
    "admin@acme.com": {
        "email": "admin@acme.com",
        "password": "admin123",
        "name": "Acme Admin",
        "tenantId": "acme-corp",
        "role": "admin",
        "tenants": ["acme-corp"]
    },
    "admin@beta.com": {
        "email": "admin@beta.com",
        "password": "admin123",
        "name": "Beta Admin",
        "tenantId": "beta-industries",
        "role": "admin",
        "tenants": ["beta-industries"]
    },
    "user@acme.com": {
        "email": "user@acme.com",
        "password": "user123",
        "name": "Acme User",
        "tenantId": "acme-corp",
        "role": "user",
        "tenants": ["acme-corp"]
    },
    "user@beta.com": {
        "email": "user@beta.com", 
        "password": "user123",
        "name": "Beta User",
        "tenantId": "beta-industries",
        "role": "user",
        "tenants": ["beta-industries"]
    },
    "superadmin@system.com": {
        "email": "superadmin@system.com",
        "password": "super123",
        "name": "Super Admin",
        "tenantId": "acme-corp",
        "role": "superadmin",
        "tenants": ["acme-corp", "beta-industries"]
    }
}

tenants = {
    "acme-corp": {"id": "acme-corp", "name": "Acme Corporation", "status": "active", "userCount": 15},
    "beta-industries": {"id": "beta-industries", "name": "Beta Industries", "status": "active", "userCount": 8}
}

# Sample sources with notification settings
sources = {
    "acme-corp": {
        1: {
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
        2: {
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
    },
    "beta-industries": {
        3: {
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
    }
}

notifications = {}
reports = {}

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
def create_jwt(user):
    payload = {
        "email": user["email"],
        "tenantId": user["tenantId"],
        "role": user["role"],
        "name": user["name"]
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Authentication endpoints
@app.get("/api/auth/tenants")
def get_user_tenants(email: str):
    """Get tenants accessible to a user by email"""
    user = users.get(email)
    if not user:
        # Return default tenants for new users
        return [
            {"id": "acme-corp", "name": "Acme Corporation"},
            {"id": "beta-industries", "name": "Beta Industries"}
        ]
    
    user_tenants = user.get("tenants", [user["tenantId"]])
    return [{
        "id": tenant_id,
        "name": tenants.get(tenant_id, {"name": tenant_id}).get("name", tenant_id)
    } for tenant_id in user_tenants]

@app.post("/api/auth/register")
def register(user_data: RegisterRequest):
    if user_data.email in users:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create tenant if it doesn't exist
    tenant_id = user_data.tenant.lower().replace(" ", "-")
    if tenant_id not in tenants:
        tenants[tenant_id] = {
            "id": tenant_id,
            "name": user_data.tenant,
            "status": "active",
            "userCount": 0
        }
    
    # Create user
    users[user_data.email] = {
        "email": user_data.email,
        "password": user_data.password,
        "name": user_data.name,
        "tenantId": tenant_id,
        "role": user_data.role,
        "tenants": [tenant_id]
    }
    
    # Update tenant user count
    tenants[tenant_id]["userCount"] += 1
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(login_data: LoginRequest):
    user = users.get(login_data.email)
    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # User can only login to their registered organization
    # No tenant selection - use their assigned tenant
    
    token = create_jwt(user)
    
    return {
        "token": token,
        "user": {
            "id": user["email"],
            "name": user["name"],
            "email": user["email"],
            "tenantId": user["tenantId"],
            "role": user["role"],
            "tenants": user.get("tenants", [user["tenantId"]])
        }
    }

# SIEM Data endpoints
@app.get("/api/sources")
def get_sources(current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    tenant_sources = sources.get(user_tenant, {})
    return list(tenant_sources.values())

@app.post("/api/sources")
def add_source(source: Source, current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    
    # Initialize tenant sources if not exists
    if user_tenant not in sources:
        sources[user_tenant] = {}
    
    # Generate new ID
    tenant_sources = sources[user_tenant]
    source_id = max(tenant_sources.keys()) + 1 if tenant_sources else 1
    
    # Create new source
    new_source = {
        "id": source_id,
        "name": source.name,
        "type": source.type,
        "ip": source.ip,
        "port": source.port,
        "protocol": source.protocol,
        "status": "active",
        "lastActivity": datetime.now().isoformat(),
        "tenant": user_tenant,
        "notifications": source.notifications or {"enabled": False, "emails": []}
    }
    
    sources[user_tenant][source_id] = new_source
    return new_source

@app.put("/api/sources/{source_id}")
def update_source(source_id: int, source: Source, current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    tenant_sources = sources.get(user_tenant, {})
    
    if source_id not in tenant_sources:
        raise HTTPException(status_code=404, detail="Source not found")
    
    # Update source
    updated_source = {
        "id": source_id,
        "name": source.name,
        "type": source.type,
        "ip": source.ip,
        "port": source.port,
        "protocol": source.protocol,
        "status": tenant_sources[source_id].get("status", "active"),
        "lastActivity": tenant_sources[source_id].get("lastActivity", datetime.now().isoformat()),
        "tenant": user_tenant,
        "notifications": source.notifications or {"enabled": False, "emails": []}
    }
    
    sources[user_tenant][source_id] = updated_source
    return updated_source

@app.delete("/api/sources/{source_id}")
def delete_source(source_id: int, current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    tenant_sources = sources.get(user_tenant, {})
    
    if source_id not in tenant_sources:
        raise HTTPException(status_code=404, detail="Source not found")
    
    del sources[user_tenant][source_id]
    return {"message": "Source deleted successfully"}

@app.get("/api/notifications")
def get_notifications(current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    # Add some mock notifications
    mock_notifications = [
        {"id": 1, "message": "High CPU usage detected", "timestamp": "2025-07-12T10:30:00Z", "tenant": user_tenant, "severity": "warning"},
        {"id": 2, "message": "Suspicious login attempt", "timestamp": "2025-07-12T11:15:00Z", "tenant": user_tenant, "severity": "critical"},
        {"id": 3, "message": "System backup completed", "timestamp": "2025-07-12T06:00:00Z", "tenant": user_tenant, "severity": "info"}
    ]
    return mock_notifications

@app.get("/api/reports")
def get_reports(current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    # Add some mock reports
    mock_reports = [
        {"id": 1, "title": "Security Summary Report", "summary": "Weekly security overview", "tenant": user_tenant, "date": "2025-07-12"},
        {"id": 2, "title": "Threat Analysis", "summary": "Analysis of recent threats", "tenant": user_tenant, "date": "2025-07-11"}
    ]
    return mock_reports

# Admin endpoints
@app.get("/api/admin/tenants")
def get_all_tenants(current=Depends(get_current_user)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Super admin can see all tenants
    if current["role"] == "superadmin":
        return list(tenants.values())
    
    # Regular admin can only see their own tenant
    user_tenant_id = current["tenantId"]
    if user_tenant_id in tenants:
        return [tenants[user_tenant_id]]
    
    return []

@app.post("/api/admin/tenants")
def create_tenant(tenant_data: dict, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    tenant_id = tenant_data["name"].lower().replace(" ", "-")
    if tenant_id in tenants:
        raise HTTPException(status_code=400, detail="Tenant already exists")
    
    tenants[tenant_id] = {
        "id": tenant_id,
        "name": tenant_data["name"],
        "status": "active",
        "userCount": 0,
        "description": tenant_data.get("description", "")
    }
    
    return tenants[tenant_id]

@app.get("/api/admin/users")
def get_all_users(tenantId: str = None, current=Depends(get_current_user)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Determine which tenants this admin can access
    accessible_tenants = []
    if current["role"] == "superadmin":
        accessible_tenants = list(tenants.keys())
    else:
        # Regular admin can only manage users in their own tenant
        accessible_tenants = [current["tenantId"]]
    
    user_list = []
    for email, user in users.items():
        # Skip users not in accessible tenants
        if user["tenantId"] not in accessible_tenants:
            continue
            
        # If specific tenant requested, filter by it
        if tenantId and user["tenantId"] != tenantId:
            continue
            
        user_info = {
            "id": email,
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "tenantId": user["tenantId"],
            "tenantName": tenants.get(user["tenantId"], {}).get("name", user["tenantId"]),
            "status": "active"  # Default status
        }
        user_list.append(user_info)
    
    return user_list

@app.post("/api/admin/users")
def create_user(user_data: RegisterRequest, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if user_data.email in users:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    users[user_data.email] = {
        "email": user_data.email,
        "password": user_data.password,
        "name": user_data.name,
        "tenantId": user_data.tenant,
        "role": user_data.role,
        "tenants": [user_data.tenant]
    }
    
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
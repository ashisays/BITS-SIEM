from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
import time
import asyncio
from datetime import datetime, timedelta

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

# In-memory user data
users_db = {
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
    }
}

# In-memory sources data
sources_db = {
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

# Initialize startup
@app.on_event("startup")
async def startup_event():
    print("Starting BITS-SIEM API in fallback mode")
    print("Database functionality disabled - using in-memory storage")

# Pydantic Models
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str
    tenantName: str

class Source(BaseModel):
    name: str
    type: str
    ip: str
    port: int
    protocol: str
    notifications: dict = {"enabled": False, "emails": []}

# JWT token creation
def create_jwt(user_data):
    payload = {
        "email": user_data["email"],
        "tenantId": user_data["tenantId"], 
        "role": user_data["role"],
        "name": user_data["name"],
        "user_id": user_data["email"],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        print(f"Validating token: {token[:20]}...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        print(f"Token payload email: {email}")
        
        if email is None:
            print("No email in token payload")
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check user in memory
        user_data = users_db.get(email)
        if not user_data:
            print(f"User not found in memory: {email}")
            raise HTTPException(status_code=401, detail="User not found")
        
        if not user_data.get("is_active", True):
            print(f"User inactive: {email}")
            raise HTTPException(status_code=401, detail="User inactive")
        
        print(f"User validation successful: {email}, tenant: {user_data['tenantId']}")
        return {
            "email": user_data["email"],
            "tenantId": user_data["tenantId"],
            "role": user_data["role"],
            "name": user_data["name"],
            "user_id": user_data["email"]
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
def register(register_data: RegisterRequest):
    if register_data.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Simple tenant ID generation
    tenant_id = register_data.tenantName.lower().replace(" ", "-")
    
    users_db[register_data.email] = {
        "email": register_data.email,
        "password": register_data.password,
        "name": register_data.name,
        "tenantId": tenant_id,
        "role": "admin",  # First user becomes admin
        "tenants": [tenant_id],
        "is_active": True
    }
    
    # Initialize empty sources for new tenant
    sources_db[tenant_id] = []
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(login_data: LoginRequest):
    try:
        print(f"Login attempt for: {login_data.email}")
        
        user_data = users_db.get(login_data.email)
        
        if not user_data or user_data["password"] != login_data.password:
            print(f"Auth failed for: {login_data.email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        if not user_data.get("is_active", True):
            print(f"User inactive: {login_data.email}")
            raise HTTPException(status_code=401, detail="Account is inactive")
        
        token = create_jwt(user_data)
        print(f"Login successful for: {user_data['email']}, tenant: {user_data['tenantId']}")
        
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

# SIEM Data endpoints
@app.get("/api/sources")
def get_sources(current=Depends(get_current_user)):
    try:
        user_tenant = current["tenantId"]
        print(f"Getting sources for tenant: {user_tenant}")
        
        tenant_sources = sources_db.get(user_tenant, [])
        print(f"Found {len(tenant_sources)} sources")
        return tenant_sources
    except Exception as e:
        print(f"Error getting sources: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving sources")

@app.post("/api/sources")
def add_source(source: Source, current=Depends(get_current_user)):
    try:
        user_tenant = current["tenantId"]
        
        # Get next ID
        all_sources = []
        for tenant_sources in sources_db.values():
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
        
        if user_tenant not in sources_db:
            sources_db[user_tenant] = []
        
        sources_db[user_tenant].append(new_source)
        print(f"Added source: {source.name} for tenant: {user_tenant}")
        
        return new_source
    except Exception as e:
        print(f"Error adding source: {e}")
        raise HTTPException(status_code=500, detail="Error adding source")

@app.put("/api/sources/{source_id}")
def update_source(source_id: int, source: Source, current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    tenant_sources = sources_db.get(user_tenant, [])
    
    for i, s in enumerate(tenant_sources):
        if s["id"] == source_id:
            sources_db[user_tenant][i].update({
                "name": source.name,
                "type": source.type,
                "ip": source.ip,
                "port": source.port,
                "protocol": source.protocol,
                "notifications": source.notifications
            })
            return sources_db[user_tenant][i]
    
    raise HTTPException(status_code=404, detail="Source not found")

@app.delete("/api/sources/{source_id}")
def delete_source(source_id: int, current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    tenant_sources = sources_db.get(user_tenant, [])
    
    for i, s in enumerate(tenant_sources):
        if s["id"] == source_id:
            deleted_source = sources_db[user_tenant].pop(i)
            return {"message": "Source deleted successfully"}
    
    raise HTTPException(status_code=404, detail="Source not found")

@app.get("/api/notifications")
def get_notifications(current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    
    # Generate sample notifications
    notifications = [
        {"id": 1, "message": "High CPU usage detected on Web Server", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "warning", "isRead": False, "metadata": {"cpu_usage": "85%"}},
        {"id": 2, "message": "Suspicious login attempt blocked", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "critical", "isRead": False, "metadata": {"ip": "192.168.1.50"}},
        {"id": 3, "message": "System backup completed successfully", "timestamp": datetime.now().isoformat(), "tenant": user_tenant, "severity": "info", "isRead": True, "metadata": {"backup_size": "2.3GB"}}
    ]
    return notifications

@app.get("/api/reports")
def get_reports(current=Depends(get_current_user)):
    user_tenant = current["tenantId"]
    
    # Generate sample reports
    reports = [
        {"id": 1, "title": "Security Summary Report", "summary": "Weekly security overview", "tenant": user_tenant, "date": datetime.now().date().isoformat(), "type": "security", "generatedBy": "system", "data": {"total_events": 1250}},
        {"id": 2, "title": "Threat Analysis Report", "summary": "Analysis of recent security threats", "tenant": user_tenant, "date": datetime.now().date().isoformat(), "type": "threat", "generatedBy": "admin", "data": {"threats_detected": 8}}
    ]
    return reports

# Admin endpoints
@app.get("/api/admin/tenants")
def get_all_tenants(current=Depends(get_current_user)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Generate tenant list from users
    tenants = {}
    for user in users_db.values():
        tenant_id = user["tenantId"]
        if tenant_id not in tenants:
            tenants[tenant_id] = {
                "id": tenant_id,
                "name": tenant_id.replace("-", " ").title(),
                "userCount": 0,
                "sourcesCount": len(sources_db.get(tenant_id, [])),
                "status": "active"
            }
        tenants[tenant_id]["userCount"] += 1
    
    return list(tenants.values())

@app.get("/api/admin/users")
def get_all_users(current=Depends(get_current_user)):
    if current["role"] not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Return all users (admin can see all for simplicity in fallback mode)
    return [
        {
            "id": user["email"],
            "name": user["name"],
            "email": user["email"],
            "tenantId": user["tenantId"],
            "role": user["role"],
            "isActive": user.get("is_active", True)
        }
        for user in users_db.values()
    ]

# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "BITS-SIEM API (Fallback Mode)",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

# WebSocket endpoint
@app.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Send periodic notifications
            await websocket.send_json({
                "type": "notification",
                "data": {
                    "message": "System status update",
                    "timestamp": datetime.now().isoformat(),
                    "severity": "info"
                }
            })
            await asyncio.sleep(30)  # Send every 30 seconds
    except WebSocketDisconnect:
        print("WebSocket disconnected")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

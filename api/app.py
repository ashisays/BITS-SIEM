from fastapi import FastAPI, WebSocket, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import List
import uvicorn
import time
import asyncio

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# In-memory stores for demo
users = {}
tenants = {}
sources = {}
notifications = {}
reports = {}

class User(BaseModel):
    email: str
    password: str
    tenant: str

class Source(BaseModel):
    id: int
    ip: str
    tenant: str

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
    return jwt.encode({"email": user["email"], "tenant": user["tenant"]}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        tenant = payload.get("tenant")
        if email is None or tenant is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"email": email, "tenant": tenant}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/api/register")
def register(user: User):
    if user.email in users:
        raise HTTPException(status_code=400, detail="User exists")
    tenants[user.tenant] = {"name": user.tenant}
    users[user.email] = {"email": user.email, "password": user.password, "tenant": user.tenant}
    return {"msg": "Registered"}

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt(user)
    return {"token": token, "user": {"email": user["email"]}, "tenant": user["tenant"]}

@app.get("/api/sources")
def get_sources(current=Depends(get_current_user)):
    return [s for s in sources.values() if s["tenant"] == current["tenant"]]

@app.post("/api/sources")
def add_source(source: Source, current=Depends(get_current_user)):
    source_id = len(sources) + 1
    sources[source_id] = {"id": source_id, "ip": source.ip, "tenant": current["tenant"]}
    return sources[source_id]

@app.delete("/api/sources/{source_id}")
def delete_source(source_id: int, current=Depends(get_current_user)):
    if source_id in sources and sources[source_id]["tenant"] == current["tenant"]:
        del sources[source_id]
        return {"msg": "Deleted"}
    raise HTTPException(status_code=404, detail="Not found")

@app.get("/api/notifications")
def get_notifications(current=Depends(get_current_user)):
    return [n for n in notifications.values() if n["tenant"] == current["tenant"]]

@app.get("/api/reports")
def get_reports(current=Depends(get_current_user)):
    return [r for r in reports.values() if r["tenant"] == current["tenant"]]

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
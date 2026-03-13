from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
import jwt
import json
import os
from cryptography.fernet import Fernet

# ── Config ────────────────────────────────────────────────────────────────
DATABASE_URL   = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://", 1)
JWT_SECRET     = os.environ.get("JWT_SECRET", "change-me-in-production")
FERNET_KEY     = os.environ.get("FERNET_KEY")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "clarifyb2b.com")

if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY env var not set. Run: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"  then add to Render env vars.")
fernet = Fernet(FERNET_KEY.encode())

# ── Database ──────────────────────────────────────────────────────────────
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id            = Column(String, primary_key=True)
    email         = Column(String, unique=True, nullable=False, index=True)
    name          = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    api_key_enc   = Column(Text, nullable=True)   # Fernet-encrypted Anthropic key
    history_json  = Column(Text, default="{}")    # JSON blob of cadence history
    created_at    = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Auth helpers ──────────────────────────────────────────────────────────
security = HTTPBearer()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "exp": datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        user = db.query(User).filter(User.id == payload["sub"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def encrypt_key(key: str) -> str:
    return fernet.encrypt(key.encode()).decode()

def decrypt_key(enc: str) -> str:
    return fernet.decrypt(enc.encode()).decode()

import uuid

# ── App ───────────────────────────────────────────────────────────────────
app = FastAPI(title="Clarify AI SDR API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Schemas ───────────────────────────────────────────────────────────────
class SignupRequest(BaseModel):
    email: str
    name: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class ApiKeyRequest(BaseModel):
    api_key: str

class HistoryRequest(BaseModel):
    history: dict

# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "Clarify AI SDR API running"}

@app.post("/auth/signup")
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    # Domain whitelist
    domain = req.email.split("@")[-1].lower()
    if domain != ALLOWED_DOMAIN.lower():
        raise HTTPException(status_code=403, detail=f"Only @{ALLOWED_DOMAIN} email addresses are allowed.")

    if db.query(User).filter(User.email == req.email.lower()).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    user = User(
        id=str(uuid.uuid4()),
        email=req.email.lower(),
        name=req.name,
        password_hash=hash_password(req.password),
        history_json="{}",
    )
    db.add(user)
    db.commit()

    token = create_token(user.id, user.email)
    return {"token": token, "name": user.name, "email": user.email}

@app.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    token = create_token(user.id, user.email)
    has_api_key = bool(user.api_key_enc)
    return {"token": token, "name": user.name, "email": user.email, "has_api_key": has_api_key}

@app.get("/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "name": current_user.name,
        "has_api_key": bool(current_user.api_key_enc),
    }

@app.put("/user/apikey")
def save_api_key(req: ApiKeyRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not req.api_key.startswith("sk-ant-"):
        raise HTTPException(status_code=400, detail="Invalid Anthropic API key format. Should start with sk-ant-")
    current_user.api_key_enc = encrypt_key(req.api_key)
    db.commit()
    return {"saved": True}

@app.get("/user/apikey")
def get_api_key(current_user: User = Depends(get_current_user)):
    if not current_user.api_key_enc:
        raise HTTPException(status_code=404, detail="No API key saved yet.")
    return {"api_key": decrypt_key(current_user.api_key_enc)}

@app.get("/user/history")
def get_history(current_user: User = Depends(get_current_user)):
    try:
        return {"history": json.loads(current_user.history_json or "{}")}
    except Exception:
        return {"history": {}}

@app.put("/user/history")
def save_history(req: HistoryRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.history_json = json.dumps(req.history)
    db.commit()
    return {"saved": True}

@app.post("/auth/refresh")
def refresh_token(current_user: User = Depends(get_current_user)):
    """Issue a fresh 30-day token so users stay logged in seamlessly."""
    token = create_token(current_user.id, current_user.email)
    return {"token": token, "name": current_user.name, "email": current_user.email}

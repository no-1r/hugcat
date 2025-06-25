from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import HTTPException
import uvicorn
import time
import os

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import DateTime, Boolean, Table 
from passlib.context import CryptContext

from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from fastapi import Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.security.utils import get_authorization_scheme_param
from jose import JWTError, jwt
from typing import Optional, List

import uuid
from dotenv import load_dotenv

load_dotenv()

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime
    
    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class FriendRequest(BaseModel):
    username: str

class FriendResponse(BaseModel):
    id: int
    username: str
    accepted: bool
    can_accept: bool
    class Config:
        orm_mode = True

class HugSessionCreate(BaseModel):
    friend_id: int

class HugSessionResponse(BaseModel):
    id: int
    session_key: str
    friend_username: str
    
    class Config:
        orm_mode = True

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

Base = declarative_base()
engine = create_engine('sqlite:///hugcat.db', connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

friendship = Table(
    'friendships', 
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('friend_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('accepted', Boolean, default=False),
    Column('created_at', DateTime, default=datetime.now(timezone.utc))
)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key = True, index = True)
    username = Column(String, unique=True, index = True, nullable = False)
    email = Column(String, unique=True, index = True, nullable = False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

    friends = relationship(
        "User", 
        secondary=friendship,
        primaryjoin=id==friendship.c.user_id,
        secondaryjoin=id==friendship.c.friend_id,
        backref="friend_of"
    )

class HugSession(Base):
    __tablename__ = 'hug_sessions'
    id = Column(Integer, primary_key=True, index=True)
    initiator_id = Column(Integer, ForeignKey('users.id'))
    recipient_id = Column(Integer, ForeignKey('users.id'))
    session_key = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    active = Column(Boolean, default=True)
    
    initiator = relationship("User", foreign_keys=[initiator_id])
    recipient = relationship("User", foreign_keys=[recipient_id])

Base.metadata.create_all(bind=engine)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-insecure-key")
if not SECRET_KEY:
    import warnings
    warnings.warn("SECRET_KEY not set! Using insecure default key. This should NEVER happen in production.")
    SECRET_KEY = "insecure-default-key-for-dev-only"
    
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Token models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Optional current user (for public sessions)
async def get_current_user_optional(request: Request, db: SessionLocal = Depends(get_db)) -> Optional[User]:
    try:
        authorization = request.headers.get("Authorization")
        if not authorization:
            return None
            
        scheme, token = get_authorization_scheme_param(authorization)
        if scheme.lower() != "bearer" or not token:
            return None
            
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        user = get_user(db, username=username)
        return user
    except:
        return None

# Ensure we get the full path
static_dir = os.path.abspath("static")
print(f"Serving static files from: {static_dir}")

app = FastAPI()
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Serve the index.html file when accessing the root
from fastapi.responses import FileResponse

@app.get("/")
async def serve_homepage():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/profile")
async def serve_profile():
    return FileResponse(os.path.join(static_dir, "profile.html"))

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Global state for public sessions
public_sessions = {}  # player_id -> {ready: bool, timestamp: float}
public_hug_active = False
public_hug_start_time = 0

# Private sessions state
hug_sessions = {}  # session_key -> {users: [], ready_users: [], active: bool, start_time: timestamp}

# Helper function to check if a session key is a private session (UUID format)
def is_private_session(session_key: str) -> bool:
    return len(session_key) >= 30 and '-' in session_key

@app.post("/hug-session/create", response_model=HugSessionResponse)
async def create_hug_session(request: HugSessionCreate, 
                           current_user: User = Depends(get_current_user), 
                           db: SessionLocal = Depends(get_db)):
    # Check if friend exists and is an accepted friend
    friend = db.query(User).filter(User.id == request.friend_id).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")
    
    friendship_exists = db.query(friendship).filter(
        ((friendship.c.user_id == current_user.id) & 
         (friendship.c.friend_id == friend.id) & 
         (friendship.c.accepted == True)) |
        ((friendship.c.user_id == friend.id) & 
         (friendship.c.friend_id == current_user.id) & 
         (friendship.c.accepted == True))
    ).first()
    
    if not friendship_exists:
        raise HTTPException(status_code=400, detail="This user is not your friend or request is pending")
    
    # Generate unique session key
    session_key = str(uuid.uuid4())
    
    # Create hug session
    new_session = HugSession(
        initiator_id=current_user.id,
        recipient_id=friend.id,
        session_key=session_key,
        active=True
    )
    
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    
    # Initialize session in memory
    hug_sessions[session_key] = {
        "users": [current_user.id, friend.id],
        "ready_users": [],
        "active": True,
        "start_time": 0
    }
    
    return {
        "id": new_session.id,
        "session_key": session_key,
        "friend_username": friend.username
    }

@app.get("/hug-session/{session_key}")
async def get_hug_session(session_key: str, 
                          current_user: User = Depends(get_current_user), 
                          db: SessionLocal = Depends(get_db)):
    # Verify session exists
    session = db.query(HugSession).filter(HugSession.session_key == session_key).first()
    if not session:
        raise HTTPException(status_code=404, detail="Hug session not found")
    
    # Verify user is part of this session
    if current_user.id != session.initiator_id and current_user.id != session.recipient_id:
        raise HTTPException(status_code=403, detail="You don't have access to this session")
    
    # Get friend info
    friend_id = session.recipient_id if current_user.id == session.initiator_id else session.initiator_id
    friend = db.query(User).filter(User.id == friend_id).first()
    
    # Make sure the in-memory session exists
    if session_key not in hug_sessions:
        # Recreate it if missing
        hug_sessions[session_key] = {
            "users": [session.initiator_id, session.recipient_id],
            "ready_users": [],
            "active": session.active,
            "start_time": 0
        }
    
    return {
        "id": session.id,
        "session_key": session_key,
        "friend_username": friend.username,
        "active": session.active,
        "created_at": session.created_at
    }

@app.post("/ready/{session_key}")
async def player_ready(session_key: str, request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    if is_private_session(session_key):
        # This is a private session
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required for private sessions")
            
        if session_key not in hug_sessions:
            raise HTTPException(status_code=404, detail="Hug session not found")
        
        # Check if user is part of this session
        if current_user.id not in hug_sessions[session_key]["users"]:
            raise HTTPException(status_code=403, detail="You don't have access to this session")
        
        # Mark user as ready
        if current_user.id not in hug_sessions[session_key]["ready_users"]:
            hug_sessions[session_key]["ready_users"].append(current_user.id)
            
        print(f"User {current_user.username} ready in session {session_key}. Ready users: {hug_sessions[session_key]['ready_users']}")
        
        return {"message": "Ready status set"}
    else:
        # This is a public session
        # Use the provided session_key as player_id for backward compatibility
        if current_user:
            player_id = str(current_user.id)
        else:
            player_id = session_key
        
        if player_id not in public_sessions:
            public_sessions[player_id] = {"ready": False, "timestamp": 0}
        
        public_sessions[player_id]["ready"] = True
        public_sessions[player_id]["timestamp"] = time.time()
        
        print(f"Player {player_id} ready in public session")
        return {"message": "Player is ready"}

@app.get("/status/{session_key}")
async def check_session_status(session_key: str):
    if is_private_session(session_key):
        # Check private session status
        if session_key not in hug_sessions:
            raise HTTPException(status_code=404, detail="Hug session not found")
        
        session = hug_sessions[session_key]
        
        # Check if hug is currently active
        if session["start_time"] > 0:
            if time.time() - session["start_time"] < 3:
                return {"status": "hug"}
            else:
                # Hug finished, reset
                session["start_time"] = 0
                session["ready_users"] = []
                return {"status": "waiting"}
        
        # Check if both users are ready
        if len(session["ready_users"]) >= 2:
            print(f"Triggering hug in session {session_key}!")
            session["start_time"] = time.time()
            return {"status": "hug"}
        
        return {"status": "waiting"}
    else:
        # This is checking public status with a specific session_key
        # For public sessions, redirect to the main status endpoint
        return await check_public_status()

@app.get("/status")
async def check_public_status():
    global public_hug_active, public_hug_start_time
    
    try:
        # Clean up old ready states (older than 30 seconds)
        current_time = time.time()
        expired_players = [pid for pid, data in public_sessions.items() 
                          if data["ready"] and current_time - data["timestamp"] > 30]
        for pid in expired_players:
            public_sessions[pid]["ready"] = False
        
        # Get currently ready players
        ready_players = [pid for pid, data in public_sessions.items() if data["ready"]]
        
        # Check if hug is currently active
        if public_hug_active:
            if time.time() - public_hug_start_time < 3:
                return {"status": "hug"}
            else:
                public_hug_active = False
        
        # If we have 2 or more ready players, start a hug
        if len(ready_players) >= 2:
            print(f"Triggering public hug! Ready players: {ready_players}")
            public_hug_active = True
            public_hug_start_time = time.time()
            
            # Reset all ready states
            for player_id in public_sessions:
                public_sessions[player_id]["ready"] = False
            
            return {"status": "hug"}
        
        return {"status": "waiting"}
        
    except Exception as e:
        print(f"Error in public status check: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/register")
async def register(user: UserCreate):
    db = SessionLocal() 

    existing_user = db.query(User).filter(User.username == user.username).first()

    if existing_user: 
        db.close()
        raise HTTPException(status_code=400, detail="username already exists")

    existing_email = db.query(User).filter(User.email == user.email).first()
    
    if existing_email:
        db.close()
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return {"user_id": new_user.id, "username": new_user.username}

@app.get("/friends", response_model=List[FriendResponse])
async def get_friends(current_user: User = Depends(get_current_user), db: SessionLocal = Depends(get_db)):
    # Get all friendships where the user is either the user or the friend
    user_friendships = db.query(friendship).filter(
        (friendship.c.user_id == current_user.id) | 
        (friendship.c.friend_id == current_user.id)
    ).all()
    result = []
    for fr in user_friendships:
        # Determine which ID is the friend's ID
        friend_id = fr.friend_id if fr.user_id == current_user.id else fr.user_id
        friend = db.query(User).filter(User.id == friend_id).first()
        
        if friend:
            result.append({
                "id": friend.id,
                "username": friend.username,
                "accepted": fr.accepted,
                "can_accept": fr.user_id != current_user.id and not fr.accepted
            })
    
    return result

@app.post("/friends/request", status_code=status.HTTP_201_CREATED)
async def send_friend_request(request: FriendRequest, 
                             current_user: User = Depends(get_current_user), 
                             db: SessionLocal = Depends(get_db)):
    # Find the user to send the friend request to
    friend = db.query(User).filter(User.username == request.username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")
    
    if friend.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot add yourself as a friend")
    
    # Check if friendship already exists
    existing = db.query(friendship).filter(
        ((friendship.c.user_id == current_user.id) & (friendship.c.friend_id == friend.id)) |
        ((friendship.c.user_id == friend.id) & (friendship.c.friend_id == current_user.id))
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Friend request already exists")
    
    # Create friendship record (not accepted yet)
    stmt = friendship.insert().values(
        user_id=current_user.id,
        friend_id=friend.id,
        accepted=False,
        created_at=datetime.now(timezone.utc)
    )
    db.execute(stmt)
    db.commit()
    
    return {"message": "Friend request sent successfully"}

@app.post("/friends/accept/{friend_id}", status_code=status.HTTP_200_OK)
async def accept_friend_request(friend_id: int, 
                               current_user: User = Depends(get_current_user), 
                               db: SessionLocal = Depends(get_db)):
    # Check if friend request exists
    friend_request = db.query(friendship).filter(
        (friendship.c.user_id == friend_id) & 
        (friendship.c.friend_id == current_user.id) &
        (friendship.c.accepted == False)
    ).first()
    
    if not friend_request:
        raise HTTPException(status_code=404, detail="Friend request not found")
    
    # Update the friendship to accepted
    stmt = friendship.update().where(
        (friendship.c.user_id == friend_id) & 
        (friendship.c.friend_id == current_user.id)
    ).values(accepted=True)
    
    db.execute(stmt)
    db.commit()
    
    return {"message": "Friend request accepted"}

@app.delete("/friends/{friend_id}", status_code=status.HTTP_200_OK)
async def remove_friend(friend_id: int, 
                       current_user: User = Depends(get_current_user), 
                       db: SessionLocal = Depends(get_db)):
    # Delete the friendship in both directions
    stmt = friendship.delete().where(
        ((friendship.c.user_id == current_user.id) & (friendship.c.friend_id == friend_id)) |
        ((friendship.c.user_id == friend_id) & (friendship.c.friend_id == current_user.id))
    )
    
    result = db.execute(stmt)
    db.commit()
    
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Friend not found")
    
    return {"message": "Friend removed successfully"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))  # Railway assigns PORT dynamically
    uvicorn.run(app, host="0.0.0.0", port=port)
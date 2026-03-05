from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app import models, schemas
from app.database import get_db
from passlib.context import CryptContext
import hashlib

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["Authentication"])

def hash_password(password: str) -> str:
    """Pre-hash password with SHA256 before bcrypt to handle long passwords"""
    # First, hash with SHA256 to get a fixed 64-char string (well under 72 byte limit)
    sha_hash = hashlib.sha256(password.encode()).hexdigest()
    # Then bcrypt hash the SHA256 result
    return pwd_context.hash(sha_hash)

def verify_password(password: str, hashed: str) -> bool:
    """Verify password by hashing with SHA256 first, then comparing"""
    sha_hash = hashlib.sha256(password.encode()).hexdigest()
    return pwd_context.verify(sha_hash, hashed)

@router.post("/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user with hashed password
    new_user = models.User(
        firstName=user.firstName,
        lastName=user.lastName,
        email=user.email,
        password_hash=hash_password(user.password)
    ) 
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=schemas.LoginResponse)
def login(login_data: schemas.LoginRequest, db: Session = Depends(get_db)):
    # Find user
    user = db.query(models.User).filter(models.User.email == login_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not found"
        )
    
    # Check password using secure verification
    if not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )
    
    return {
        "message": "Login successful",
        "user": user
    }
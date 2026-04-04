from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from uuid import UUID
from app import models, schemas
from app.database import get_db
from app.security import create_access_token, get_current_user
from passlib.context import CryptContext


# Use Argon2id for new passwords and keep legacy schemes for migration.
pwd_context = CryptContext(schemes=["argon2", "bcrypt_sha256", "bcrypt"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["Authentication"])


def hash_password(password: str) -> str:
    """Hash password using the primary scheme (Argon2id)."""
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against stored hash (argon2, bcrypt_sha256, or bcrypt)."""
    try:
        return pwd_context.verify(password, hashed)
    except ValueError:
        # Some legacy bcrypt hashes may raise when input exceeds 72 bytes.
        # Retry with bcrypt-compatible byte truncation for backward compatibility.
        truncated = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
        return pwd_context.verify(truncated, hashed)

@router.post("/register", response_model=schemas.TokenResponse)
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
    
    # Create JWT token for auto-login
    access_token = create_access_token(data={"sub": new_user.email})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": new_user
    }

@router.post("/login", response_model=schemas.TokenResponse)
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

    # Auto-upgrade legacy hashes to Argon2id after successful login.
    if pwd_context.needs_update(user.password_hash):
        user.password_hash = hash_password(login_data.password)
        db.commit()
        db.refresh(user)
    
    # Create JWT token
    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/users/search", response_model=List[schemas.UserSearchResult])
def search_users(
    q: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Search non-admin users by name or email (excludes the caller)."""
    query = q.strip()
    if len(query) < 2:
        return []

    pattern = f"%{query}%"
    users = (
        db.query(models.User)
        .filter(
            models.User.is_admin == False,
            models.User.email != current_user_email,
            func.lower(models.User.firstName).like(func.lower(pattern))
            | func.lower(models.User.lastName).like(func.lower(pattern))
            | func.lower(models.User.email).like(func.lower(pattern)),
        )
        .limit(10)
        .all()
    )
    return [
        {
            "id": user.id,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "email": user.email,
            "has_public_key": bool(user.public_key),
        }
        for user in users
    ]


@router.put("/me/public-key", response_model=schemas.UserPublicKeyResponse)
def upsert_my_public_key(
    payload: schemas.UserPublicKeyUpdateRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Publish or update the authenticated user's public key."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.public_key = payload.public_key
    db.commit()
    db.refresh(user)
    return {"user_id": user.id, "public_key": user.public_key}


@router.get("/users/{user_id}/public-key", response_model=schemas.UserPublicKeyResponse)
def get_user_public_key(
    user_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Fetch recipient public key for client-side DEK wrapping (placeholder endpoint)."""
    _ = current_user_email  # Auth guard only; any logged-in user may fetch public keys.

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format")

    user = db.query(models.User).filter(models.User.id == user_uuid).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user.public_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User has not published a public key yet"
        )

    return {"user_id": user.id, "public_key": user.public_key}
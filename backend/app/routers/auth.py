from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from app import models, schemas
from app.database import get_db
from passlib.context import CryptContext
import base64
import os

# password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Register user and generate encrypted master key

    Flow:
    1. Generate random 32-byte master key
    2. Generate salt for key encryption
    3. Derive key encryption key from password + salt using PBKDF2
    4. Encrypt master key with the derived key
    5. Encrypt password with bcrypt
    6. Store all in database
    """
    # Check if user already exists
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Generate random master key (32 bytes for NaCl secretbox)
    master_key = os.urandom(32)

    # Generate salt for key encryption (16 bytes)
    key_encryption_salt = os.urandom(16)

    # The frontend will use PBKDF2 to derive a key from password + this salt
    # We encrypt the master key with that derived key on the frontend
    # For now, we'll do it here: derive the encryption key from password
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import nacl.secret
    import nacl.utils

    # Derive key encryption key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=key_encryption_salt,
        iterations=100000,
        backend=default_backend()
    )
    key_encryption_key = kdf.derive(user.password.encode())

    # Encrypt master key using NaCl secretbox
    box = nacl.secret.SecretBox(key_encryption_key)
    encrypted_master_key = box.encrypt(master_key)

    # Encode as base64 for storage
    encrypted_master_key_b64 = base64.b64encode(bytes(encrypted_master_key)).decode()
    key_encryption_salt_b64 = base64.b64encode(key_encryption_salt).decode()

    # Hash password with bcrypt
    hashed_password = pwd_context.hash(user.password)

    # Create user with encrypted master key
    new_user = models.User(
        firstName=user.firstName,
        lastName=user.lastName,
        email=user.email,
        password_hash=hashed_password,
        encrypted_master_key=encrypted_master_key_b64,
        master_key_salt=key_encryption_salt_b64
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

@router.post("/login", response_model=schemas.LoginResponse)
def login(login_data: schemas.LoginRequest, db: Session = Depends(get_db)):
    """
    Login user and return decrypted master key

    Flow:
    1. Find user by email
    2. Verify password
    3. Decrypt master key using password + stored salt
    4. Return master key to frontend for storing in sessionStorage
    """
    # Find user
    user = db.query(models.User).filter(models.User.email == login_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not found"
        )

    # Verify password using bcrypt
    if not pwd_context.verify(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Decrypt master key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import nacl.secret

    # Retrieve stored salt and encrypted key
    key_encryption_salt = base64.b64decode(user.master_key_salt)
    encrypted_master_key_bytes = base64.b64decode(user.encrypted_master_key)

    # Derive key encryption key from password + salt (same as during signup)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=key_encryption_salt,
        iterations=100000,
        backend=default_backend()
    )
    key_encryption_key = kdf.derive(login_data.password.encode())

    # Decrypt master key
    try:
        box = nacl.secret.SecretBox(key_encryption_key)
        master_key = box.decrypt(encrypted_master_key_bytes)
        master_key_b64 = base64.b64encode(master_key).decode()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to decrypt master key"
        )

    return {
        "message": "Login successful",
        "user": user,
        "master_key": master_key_b64  # Send encrypted master key to frontend
    }
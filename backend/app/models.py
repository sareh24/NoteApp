from sqlalchemy import Column, String, LargeBinary, Integer, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    firstName = Column(String, nullable=False)
    lastName = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    # Encryption key management
    encrypted_master_key = Column(String, nullable=False)  # User's master key encrypted with password-derived key
    master_key_salt = Column(String, nullable=False)  # Salt for deriving key encryption key
    current_epoch = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Note(Base):
    __tablename__ = "notes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    content_ciphertext = Column(String, nullable=False)  # Encrypted note content
    is_public = Column(Boolean, default=False)
    epoch = Column(Integer, default=0)  # For future UE implementation
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


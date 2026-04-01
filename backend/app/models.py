from sqlalchemy import Column, String, LargeBinary, Integer, DateTime, ForeignKey, Text, Boolean, Uuid, UniqueConstraint
from datetime import datetime
import uuid
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    firstName = Column(String, nullable=False)
    lastName = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    # Placeholder for future asymmetric sharing: public key published by user.
    public_key = Column(Text, nullable=True)
    is_admin = Column(Boolean, default=False)
    current_epoch = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class Note(Base):
    __tablename__ = "notes"
    
    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False, default="Untitled Note")
    content = Column(Text, nullable=False)
    is_public = Column(Boolean, default=False)
    encrypted_dek = Column(Text, nullable=True)  # only set for private notes
    key_version = Column(String, nullable=True)  # tracks which key was used, for rotation
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SharedNote(Base):
    __tablename__ = "shared_notes"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    note_id = Column(Uuid(as_uuid=True), ForeignKey("notes.id", ondelete="CASCADE"), nullable=False)
    recipient_id = Column(Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    can_edit = Column(Boolean, default=False)
    # Placeholder for future asymmetric sharing: recipient-wrapped DEK.
    recipient_encrypted_dek = Column(Text, nullable=True)
    recipient_key_version = Column(String, nullable=True)
    shared_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("note_id", "recipient_id", name="uq_shared_note_recipient"),)


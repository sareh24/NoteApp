from pydantic import BaseModel, EmailStr
from datetime import datetime
from uuid import UUID

class UserCreate(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: UUID
    firstName: str
    lastName: str
    email: str
    current_epoch: int
    created_at: datetime

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    message: str
    user: UserResponse
    master_key: str = None  # Base64 encoded master key sent to frontend

class NoteCreate(BaseModel):
    title: str
    content_ciphertext: str  # Encrypted content from frontend
    is_public: bool = False

class NoteUpdate(BaseModel):
    title: str
    content_ciphertext: str
    is_public: bool = False

class NoteResponse(BaseModel):
    id: UUID
    user_id: UUID
    title: str
    content_ciphertext: str
    is_public: bool
    epoch: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class NoteList(BaseModel):
    notes: list[NoteResponse]
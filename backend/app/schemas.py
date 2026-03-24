from pydantic import BaseModel, EmailStr
from datetime import datetime
from uuid import UUID
from typing import Optional

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
    is_admin: bool
    current_epoch: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class LoginResponse(BaseModel):
    message: str
    user: UserResponse

class NoteCreate(BaseModel):
    title: Optional[str] = "Untitled Note"
    content: str
    is_public: bool = False
    encrypted_dek: Optional[str] = None
    key_version: Optional[str] = None

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    is_public: Optional[bool] = None

class NoteResponse(BaseModel):
    id: UUID
    user_id: UUID
    title: str
    content: str
    is_public: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True
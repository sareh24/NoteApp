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
    encrypted_dek: Optional[str] = None
    key_version: Optional[str] = None

class NoteResponse(BaseModel):
    id: UUID
    user_id: UUID
    title: str
    content: str
    is_public: bool
    encrypted_dek: Optional[str] = None
    key_version: Optional[str] = None
    can_edit: bool = False
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ShareNoteRequest(BaseModel):
    recipient_id: UUID
    can_edit: bool = False

class UserSearchResult(BaseModel):
    id: UUID
    firstName: str
    lastName: str
    email: str

    class Config:
        from_attributes = True

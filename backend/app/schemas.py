from pydantic import BaseModel, EmailStr
from datetime import datetime
from uuid import UUID
from typing import List, Optional

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


class UserPublicKeyUpdateRequest(BaseModel):
    public_key: str


class UserPublicKeyResponse(BaseModel):
    user_id: UUID
    public_key: str


class NoteKeyPacketPayload(BaseModel):
    recipient_user_id: UUID
    gk_version: int
    enc_gk_b64: str
    fingerprint_b64: Optional[str] = None


class NoteVersionPayload(BaseModel):
    version: int
    gk_version: int
    content_nonce_b64: str
    content_ciphertext_b64: str
    wrapped_dek_b64: str


class NoteVersionResponse(NoteVersionPayload):
    created_at: datetime

class NoteCreate(BaseModel):
    note_id: Optional[UUID] = None
    title: Optional[str] = "Untitled Note"
    content: Optional[str] = None
    is_public: bool = False
    initial_version: Optional[NoteVersionPayload] = None
    key_packets: List[NoteKeyPacketPayload] = []

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    is_public: Optional[bool] = None
    next_version: Optional[NoteVersionPayload] = None

class NoteResponse(BaseModel):
    id: UUID
    user_id: UUID
    title: str
    content: Optional[str] = None
    is_public: bool
    encrypted_dek: Optional[str] = None
    key_version: Optional[str] = None
    uses_protocol: bool = False
    current_version: int = 0
    current_gk_version: int = 0
    rotation_due: bool = False
    latest_version: Optional[NoteVersionResponse] = None
    my_enc_gk_b64: Optional[str] = None
    my_gk_version: Optional[int] = None
    my_fingerprint_b64: Optional[str] = None
    my_is_confidential: bool = False
    is_owner: bool = False
    can_edit: bool = False
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ShareNoteRequest(BaseModel):
    recipient_id: UUID
    can_edit: bool = False
    is_confidential: bool = False
    gk_version: int
    enc_gk_b64: str
    fingerprint_b64: Optional[str] = None


class RotateGroupKeyRequest(BaseModel):
    new_gk_version: int
    update_token_b64: str
    revoked_recipient_id: Optional[UUID] = None
    key_packets: List[NoteKeyPacketPayload]


class DetectFingerprintRequest(BaseModel):
    fingerprint_b64: str


class SharedRecipientResponse(BaseModel):
    recipient_id: UUID
    firstName: str
    lastName: str
    email: str
    can_edit: bool
    shared_at: datetime

class UserSearchResult(BaseModel):
    id: UUID
    firstName: str
    lastName: str
    email: str
    has_public_key: bool = False

    class Config:
        from_attributes = True

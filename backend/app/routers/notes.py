from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID
from app import models, schemas
from app.database import get_db
from app.security import get_current_user

router = APIRouter(prefix="/notes", tags=["Notes"])

@router.post("/", response_model=schemas.NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    note: schemas.NoteCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Create a new note for the authenticated user"""
    # Get user from email
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Public notes are stored in plaintext and do not keep encryption metadata.
    encrypted_dek = None if note.is_public else note.encrypted_dek
    key_version = None if note.is_public else note.key_version

    # Create new note
    new_note = models.Note(
        user_id=user.id,
        title=note.title,
        content=note.content,
        is_public=note.is_public,
        encrypted_dek=encrypted_dek,
        key_version=key_version
    )
    
    db.add(new_note)
    db.commit()
    db.refresh(new_note)
    
    return new_note

@router.get("/", response_model=List[schemas.NoteResponse])
async def get_user_notes(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Get all notes for the authenticated user"""
    # Get user from email
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Admin can view public notes from everyone and all of their own notes.
    # Regular users only see their own notes in this endpoint.
    if user.is_admin:
        notes = db.query(models.Note).filter(
            (models.Note.is_public == True) | (models.Note.user_id == user.id)
        ).order_by(models.Note.updated_at.desc()).all()
    else:
        notes = db.query(models.Note).filter(
            models.Note.user_id == user.id
        ).order_by(models.Note.updated_at.desc()).all()

    for note in notes:
        note.can_edit = (not user.is_admin) and (note.user_id == user.id)
    
    return notes

@router.get("/shared", response_model=List[schemas.NoteResponse])
async def get_shared_notes(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Get notes explicitly shared with the authenticated non-admin user."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_admin:
        return []

    shared_note_ids = (
        db.query(models.SharedNote.note_id)
        .filter(models.SharedNote.recipient_id == user.id)
        .subquery()
    )
    notes = db.query(models.Note).filter(
        models.Note.id.in_(shared_note_ids)
    ).order_by(models.Note.updated_at.desc()).all()

    permission_map = {
        row.note_id: bool(row.can_edit)
        for row in db.query(models.SharedNote.note_id, models.SharedNote.can_edit)
        .filter(models.SharedNote.recipient_id == user.id)
        .all()
    }
    for note in notes:
        note.can_edit = permission_map.get(note.id, False)

    return notes

@router.get("/public", response_model=List[schemas.NoteResponse])
def get_public_notes(db: Session = Depends(get_db)):
    """Get all public notes"""
    notes = db.query(models.Note).filter(models.Note.is_public == True).order_by(models.Note.updated_at.desc()).all()
    return notes

@router.get("/{note_id}", response_model=schemas.NoteResponse)
async def get_note(
    note_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Get a specific note by ID"""
    # Get user from email
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    try:
        note_uuid = UUID(note_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid note ID format"
        )

    shared_access = db.query(models.SharedNote).filter(
        models.SharedNote.note_id == note_uuid,
        models.SharedNote.recipient_id == user.id
    ).first()
    note = db.query(models.Note).filter(models.Note.id == note_uuid).first()
    
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    if not (note.is_public or note.user_id == user.id or shared_access):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    if user.is_admin:
        note.can_edit = False
    elif note.user_id == user.id:
        note.can_edit = True
    elif shared_access:
        note.can_edit = bool(shared_access.can_edit)
    else:
        note.can_edit = False
    
    return note

@router.put("/{note_id}", response_model=schemas.NoteResponse)
async def update_note(
    note_id: str,
    note_update: schemas.NoteUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Update a note"""
    # Get user from email
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot edit notes"
        )
    
    try:
        note_uuid = UUID(note_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid note ID format"
        )

    note = db.query(models.Note).filter(models.Note.id == note_uuid).first()
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )

    is_owner = note.user_id == user.id
    shared_access = None
    if not is_owner:
        shared_access = db.query(models.SharedNote).filter(
            models.SharedNote.note_id == note_uuid,
            models.SharedNote.recipient_id == user.id
        ).first()
        if not shared_access:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Note not found"
            )
        if not shared_access.can_edit:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Owner has not allowed editing for this shared note"
            )
    
    # Update fields if provided
    if note_update.title is not None:
        note.title = note_update.title
    if note_update.content is not None:
        note.content = note_update.content

    if is_owner:
        if note_update.is_public is not None:
            note.is_public = note_update.is_public

        # Allow metadata updates for private-note envelope encryption.
        if "encrypted_dek" in note_update.model_fields_set:
            note.encrypted_dek = note_update.encrypted_dek
        if "key_version" in note_update.model_fields_set:
            note.key_version = note_update.key_version

        # Public notes should not carry private encryption metadata.
        if note.is_public:
            note.encrypted_dek = None
            note.key_version = None
    else:
        # Shared editors cannot change ownership-level visibility/encryption controls.
        if note_update.is_public is not None or "encrypted_dek" in note_update.model_fields_set or "key_version" in note_update.model_fields_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Shared editors can only update title and content"
            )
    
    db.commit()
    db.refresh(note)

    note.can_edit = True
    
    return note

@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(
    note_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Delete a note"""
    # Get user from email
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    try:
        note_uuid = UUID(note_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid note ID format"
        )

    # Only owners can delete notes.
    note_query = db.query(models.Note).filter(models.Note.id == note_uuid)
    note_query = note_query.filter(models.Note.user_id == user.id)
    note = note_query.first()
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )
    
    db.delete(note)
    db.commit()
    
    return None

@router.post("/{note_id}/share", status_code=status.HTTP_200_OK)
async def share_note(
    note_id: str,
    share_data: schemas.ShareNoteRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user)
):
    """Share a note with another user. Only the note owner can share it."""
    user = db.query(models.User).filter(models.User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins cannot share notes")

    try:
        note_uuid = UUID(note_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid note ID format")

    note = db.query(models.Note).filter(
        models.Note.id == note_uuid,
        models.Note.user_id == user.id
    ).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    recipient = db.query(models.User).filter(models.User.id == share_data.recipient_id).first()
    if not recipient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found")

    if recipient.id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot share a note with yourself")

    existing = db.query(models.SharedNote).filter(
        models.SharedNote.note_id == note_uuid,
        models.SharedNote.recipient_id == recipient.id
    ).first()
    if existing:
        existing.can_edit = share_data.can_edit
        db.commit()
        message = "Share permissions updated"
        mode = "can edit" if share_data.can_edit else "read only"
        return {"message": f"{message}: {recipient.firstName} {recipient.lastName} is now {mode}"}

    shared = models.SharedNote(note_id=note_uuid, recipient_id=recipient.id, can_edit=share_data.can_edit)
    db.add(shared)
    db.commit()
    mode = "with edit access" if share_data.can_edit else "as read only"
    return {"message": f"Note shared with {recipient.firstName} {recipient.lastName} {mode}"}

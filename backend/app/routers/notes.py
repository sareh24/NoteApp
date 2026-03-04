from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from uuid import UUID
from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/notes", tags=["Notes"])

# Helper function to get user_id from header
def get_user_id(user_id: str = Header(...)) -> UUID:
    try:
        return UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user_id format")

@router.post("/create", response_model=schemas.NoteResponse)
def create_note(
    note: schemas.NoteCreate,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_user_id)
):
    """Create a new encrypted note"""
    # Verify user exists
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Create note
    new_note = models.Note(
        user_id=user_id,
        title=note.title,
        content_ciphertext=note.content_ciphertext,
        is_public=note.is_public
    )
    db.add(new_note)
    db.commit()
    db.refresh(new_note)
    return new_note

@router.get("/", response_model=list[schemas.NoteResponse])
def get_user_notes(
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_user_id)
):
    """Get all notes for the authenticated user"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    notes = db.query(models.Note).filter(models.Note.user_id == user_id).all()
    return notes

@router.get("/{note_id}", response_model=schemas.NoteResponse)
def get_note(
    note_id: UUID,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_user_id)
):
    """Get a specific note (must be owner)"""
    note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.user_id == user_id
    ).first()

    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    return note

@router.put("/{note_id}", response_model=schemas.NoteResponse)
def update_note(
    note_id: UUID,
    note_update: schemas.NoteUpdate,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_user_id)
):
    """Update a note (must be owner)"""
    note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.user_id == user_id
    ).first()

    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    note.title = note_update.title
    note.content_ciphertext = note_update.content_ciphertext
    note.is_public = note_update.is_public

    db.commit()
    db.refresh(note)
    return note

@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    note_id: UUID,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_user_id)
):
    """Delete a note (must be owner)"""
    note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.user_id == user_id
    ).first()

    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    db.delete(note)
    db.commit()
    return None

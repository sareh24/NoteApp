from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
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
    
    # Create new note
    new_note = models.Note(
        user_id=user.id,
        title=note.title,
        content=note.content,
        is_public=note.is_public,
        encrypted_dek=note.encrypted_dek,  # None for public notes
        key_version=note.key_version       # None for public notes
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
    
    # Get all notes for this user, ordered by most recent first
    notes = db.query(models.Note).filter(
        models.Note.user_id == user.id
    ).order_by(models.Note.updated_at.desc()).all()
    
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
    
    # Get the note
    note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.user_id == user.id
    ).first()
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )
    
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
    
    # Get the note
    note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.user_id == user.id
    ).first()
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )
    
    # Update fields if provided
    if note_update.title is not None:
        note.title = note_update.title
    if note_update.content is not None:
        note.content = note_update.content
    if note_update.is_public is not None:
        note.is_public = note_update.is_public
    
    db.commit()
    db.refresh(note)
    
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
    
    # Get the note
    note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.user_id == user.id
    ).first()
    
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )
    
    db.delete(note)
    db.commit()
    
    return None


def encrypt_content(content: str, user_id: str) -> str:
    # TODO: implement real encryption (AES-256-GCM + DEK/KEK scheme)
    return content

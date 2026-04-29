import base64
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.security import get_current_user

router = APIRouter(prefix="/notes", tags=["Notes"])


def get_user_or_404(db: Session, email: str) -> models.User:
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def get_note_or_404(db: Session, note_uuid: UUID) -> models.Note:
    note = db.query(models.Note).filter(models.Note.id == note_uuid).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return note


def parse_note_uuid(note_id: str) -> UUID:
    try:
        return UUID(note_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid note ID format") from exc


def get_shared_access(db: Session, note_uuid: UUID, user_id: UUID) -> Optional[models.SharedNote]:
    return db.query(models.SharedNote).filter(
        models.SharedNote.note_id == note_uuid,
        models.SharedNote.recipient_id == user_id,
    ).first()


def get_latest_version(db: Session, note: models.Note) -> Optional[models.NoteVersion]:
    if note.current_version <= 0:
        return None
    return db.query(models.NoteVersion).filter(
        models.NoteVersion.note_id == note.id,
        models.NoteVersion.version == note.current_version,
    ).first()


def get_key_packet(db: Session, note_id: UUID, recipient_id: UUID, gk_version: int) -> Optional[models.NoteKeyPacket]:
    return db.query(models.NoteKeyPacket).filter(
        models.NoteKeyPacket.note_id == note_id,
        models.NoteKeyPacket.recipient_id == recipient_id,
        models.NoteKeyPacket.gk_version == gk_version,
    ).first()


def serialize_note_version(version: Optional[models.NoteVersion]) -> Optional[dict]:
    if not version:
        return None
    return {
        "version": version.version,
        "gk_version": version.gk_version,
        "content_nonce_b64": version.content_nonce_b64,
        "content_ciphertext_b64": version.content_ciphertext_b64,
        "wrapped_dek_b64": version.wrapped_dek_b64,
        "created_at": version.created_at,
    }


def serialize_note(
    note: models.Note,
    current_user: Optional[models.User] = None,
    *,
    can_edit: bool = False,
    include_latest_version: bool = False,
    db: Optional[Session] = None,
) -> dict:
    latest_version = get_latest_version(db, note) if include_latest_version and db else None
    is_owner = bool(current_user and note.user_id == current_user.id)
    my_packet = None
    my_share = None
    if db and current_user and note.uses_protocol and not note.is_public and note.current_gk_version > 0:
        my_packet = get_key_packet(db, note.id, current_user.id, note.current_gk_version)
    if db and current_user and not is_owner:
        my_share = get_shared_access(db, note.id, current_user.id)

    content = note.content
    if note.uses_protocol and not note.is_public:
        content = None

    result = {
        "id": note.id,
        "user_id": note.user_id,
        "title": note.title,
        "content": content,
        "is_public": note.is_public,
        "encrypted_dek": note.encrypted_dek,
        "key_version": note.key_version,
        "uses_protocol": bool(note.uses_protocol),
        "current_version": note.current_version or 0,
        "current_gk_version": note.current_gk_version or 0,
        "rotation_due": bool(note.rotation_due),
        "latest_version": serialize_note_version(latest_version),
        "my_enc_gk_b64": my_packet.enc_gk_b64 if my_packet else None,
        "my_gk_version": my_packet.gk_version if my_packet else None,
        "my_fingerprint_b64": my_packet.fingerprint_b64 if my_packet else None,
        "is_owner": is_owner,
        "can_edit": can_edit,
        "author_name": None,
        "author_email": None,
        "created_at": note.created_at,
        "updated_at": note.updated_at,
    }

    if db and note.is_public:
        author = db.query(models.User).filter(models.User.id == note.user_id).first()
        if author:
            result["author_name"] = author.firstName
            result["author_email"] = author.email

    return result


def validate_key_packets(key_packets: List[schemas.NoteKeyPacketPayload], expected_gk_version: int) -> None:
    seen_recipients = set()
    for packet in key_packets:
        if packet.gk_version != expected_gk_version:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="All key packets must use the expected group-key version",
            )
        if packet.recipient_user_id in seen_recipients:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Duplicate key packet recipient",
            )
        seen_recipients.add(packet.recipient_user_id)


@router.post("/", response_model=schemas.NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    note: schemas.NoteCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)

    if note.is_public:
        if not note.content:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Public notes require content")

        new_note = models.Note(
            id=note.note_id,
            user_id=user.id,
            title=note.title or "Untitled Note",
            content=note.content,
            is_public=True,
            uses_protocol=False,
        )
        db.add(new_note)
        db.commit()
        db.refresh(new_note)
        return serialize_note(new_note, user, can_edit=True)

    if not note.initial_version:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Private protocol notes require an initial version")
    if note.initial_version.version != 1 or note.initial_version.gk_version != 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Initial private note must start at version 1 and group-key version 1")
    if not note.key_packets:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Private protocol notes require at least one key packet")

    validate_key_packets(note.key_packets, expected_gk_version=1)
    packet_recipient_ids = {packet.recipient_user_id for packet in note.key_packets}
    if user.id not in packet_recipient_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner key packet is required")

    new_note = models.Note(
        id=note.note_id,
        user_id=user.id,
        title=note.title or "Untitled Note",
        content="",
        is_public=False,
        uses_protocol=True,
        current_version=1,
        current_gk_version=1,
        rotation_due=False,
        last_gk_rotated_at=datetime.utcnow(),
    )
    db.add(new_note)
    db.flush()

    version = models.NoteVersion(
        note_id=new_note.id,
        version=note.initial_version.version,
        gk_version=note.initial_version.gk_version,
        content_nonce_b64=note.initial_version.content_nonce_b64,
        content_ciphertext_b64=note.initial_version.content_ciphertext_b64,
        wrapped_dek_b64=note.initial_version.wrapped_dek_b64,
    )
    db.add(version)

    for packet in note.key_packets:
        db.add(
            models.NoteKeyPacket(
                note_id=new_note.id,
                recipient_id=packet.recipient_user_id,
                gk_version=packet.gk_version,
                enc_gk_b64=packet.enc_gk_b64,
            )
        )
        if packet.recipient_user_id != user.id:
            existing_share = get_shared_access(db, new_note.id, packet.recipient_user_id)
            if not existing_share:
                db.add(
                    models.SharedNote(
                        note_id=new_note.id,
                        recipient_id=packet.recipient_user_id,
                        can_edit=False,
                    )
                )

    db.commit()
    db.refresh(new_note)
    return serialize_note(new_note, user, can_edit=True, include_latest_version=True, db=db)


@router.get("/", response_model=List[schemas.NoteResponse])
async def get_user_notes(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)

    if user.is_admin:
        notes = db.query(models.Note).filter(
            (models.Note.is_public == True) | (models.Note.user_id == user.id)
        ).order_by(models.Note.updated_at.desc()).all()
    else:
        notes = db.query(models.Note).filter(models.Note.user_id == user.id).order_by(models.Note.updated_at.desc()).all()

    return [serialize_note(note, user, can_edit=(not user.is_admin) and (note.user_id == user.id)) for note in notes]


@router.get("/shared", response_model=List[schemas.NoteResponse])
async def get_shared_notes(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    if user.is_admin:
        return []

    shared_note_ids = (
        db.query(models.SharedNote.note_id)
        .filter(models.SharedNote.recipient_id == user.id)
        .subquery()
    )
    notes = db.query(models.Note).filter(models.Note.id.in_(shared_note_ids)).order_by(models.Note.updated_at.desc()).all()

    permission_map = {
        row.note_id: bool(row.can_edit)
        for row in db.query(models.SharedNote.note_id, models.SharedNote.can_edit)
        .filter(models.SharedNote.recipient_id == user.id)
        .all()
    }
    return [serialize_note(note, user, can_edit=permission_map.get(note.id, False)) for note in notes]


@router.get("/public", response_model=List[schemas.NoteResponse])
def get_public_notes(db: Session = Depends(get_db)):
    notes = db.query(models.Note).filter(models.Note.is_public == True).order_by(models.Note.updated_at.desc()).all()
    return [serialize_note(note, db=db) for note in notes]


@router.get("/{note_id}/shares", response_model=List[schemas.SharedRecipientResponse])
async def get_note_shares(
    note_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    note_uuid = parse_note_uuid(note_id)
    note = get_note_or_404(db, note_uuid)

    if note.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the note owner can view sharing details")

    shared_rows = (
        db.query(models.SharedNote, models.User)
        .join(models.User, models.User.id == models.SharedNote.recipient_id)
        .filter(models.SharedNote.note_id == note_uuid)
        .order_by(models.SharedNote.shared_at.desc())
        .all()
    )
    return [
        {
            "recipient_id": recipient.id,
            "firstName": recipient.firstName,
            "lastName": recipient.lastName,
            "email": recipient.email,
            "can_edit": bool(share.can_edit),
            "shared_at": share.shared_at,
        }
        for share, recipient in shared_rows
    ]


@router.get("/{note_id}", response_model=schemas.NoteResponse)
async def get_note(
    note_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    note_uuid = parse_note_uuid(note_id)
    note = get_note_or_404(db, note_uuid)
    shared_access = get_shared_access(db, note_uuid, user.id)

    if not (note.is_public or note.user_id == user.id or shared_access):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    can_edit = False
    if not user.is_admin:
        if note.user_id == user.id:
            can_edit = True
        elif shared_access:
            can_edit = bool(shared_access.can_edit)

    response = serialize_note(note, user, can_edit=can_edit, include_latest_version=True, db=db)

    if note.uses_protocol and not note.is_public and not response["my_enc_gk_b64"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No group-key packet available for this user")

    return response


@router.put("/{note_id}", response_model=schemas.NoteResponse)
async def update_note(
    note_id: str,
    note_update: schemas.NoteUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    if user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins cannot edit notes")

    note_uuid = parse_note_uuid(note_id)
    note = get_note_or_404(db, note_uuid)
    is_owner = note.user_id == user.id
    shared_access = None if is_owner else get_shared_access(db, note_uuid, user.id)

    if not is_owner:
        if not shared_access:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
        if not shared_access.can_edit:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner has not allowed editing for this shared note")

    if note.uses_protocol and not note.is_public:
        if note_update.is_public is not None and note_update.is_public != note.is_public:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Changing visibility is not supported for protocol-managed private notes")
        if not note_update.next_version:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Protocol-managed private notes require a next version payload")
        expected_version = (note.current_version or 0) + 1
        if note_update.next_version.version != expected_version:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect note version number")
        if note_update.next_version.gk_version != note.current_gk_version:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect group-key version for this note update")

        if note_update.title is not None:
            note.title = note_update.title

        new_version = models.NoteVersion(
            note_id=note.id,
            version=note_update.next_version.version,
            gk_version=note_update.next_version.gk_version,
            content_nonce_b64=note_update.next_version.content_nonce_b64,
            content_ciphertext_b64=note_update.next_version.content_ciphertext_b64,
            wrapped_dek_b64=note_update.next_version.wrapped_dek_b64,
        )
        db.add(new_version)
        note.current_version = note_update.next_version.version
        note.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(note)
        return serialize_note(note, user, can_edit=True, include_latest_version=True, db=db)

    if note_update.title is not None:
        note.title = note_update.title
    if note_update.content is not None:
        note.content = note_update.content
    if is_owner and note_update.is_public is not None:
        note.is_public = note_update.is_public

    note.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(note)
    return serialize_note(note, user, can_edit=True, include_latest_version=False, db=db)


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(
    note_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    note_uuid = parse_note_uuid(note_id)
    note = db.query(models.Note).filter(models.Note.id == note_uuid, models.Note.user_id == user.id).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    db.delete(note)
    db.commit()
    return None


@router.post("/{note_id}/share", status_code=status.HTTP_200_OK)
async def share_note(
    note_id: str,
    share_data: schemas.ShareNoteRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    if user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins cannot share notes")

    note_uuid = parse_note_uuid(note_id)
    note = db.query(models.Note).filter(models.Note.id == note_uuid, models.Note.user_id == user.id).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    if note.is_public:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Public notes do not require sharing")
    if not note.uses_protocol:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Private sharing is only supported for protocol-managed notes")
    if share_data.gk_version != note.current_gk_version:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Share packet must target the current group-key version")

    recipient = db.query(models.User).filter(models.User.id == share_data.recipient_id).first()
    if not recipient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found")
    if recipient.id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot share a note with yourself")

    existing_share = get_shared_access(db, note_uuid, recipient.id)
    if existing_share:
        existing_share.can_edit = share_data.can_edit
    else:
        db.add(models.SharedNote(note_id=note_uuid, recipient_id=recipient.id, can_edit=share_data.can_edit))

    existing_packet = get_key_packet(db, note_uuid, recipient.id, share_data.gk_version)
    if existing_packet:
        existing_packet.enc_gk_b64 = share_data.enc_gk_b64
        existing_packet.fingerprint_b64 = share_data.fingerprint_b64
    else:
        db.add(
            models.NoteKeyPacket(
                note_id=note_uuid,
                recipient_id=recipient.id,
                gk_version=share_data.gk_version,
                enc_gk_b64=share_data.enc_gk_b64,
                fingerprint_b64=share_data.fingerprint_b64,
            )
        )

    db.commit()
    mode = "can edit" if share_data.can_edit else "read only"
    return {"message": f"Share permissions updated: {recipient.firstName} {recipient.lastName} is now {mode}"}


@router.post("/{note_id}/rotate-group-key", status_code=status.HTTP_200_OK)
async def rotate_group_key(
    note_id: str,
    payload: schemas.RotateGroupKeyRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = get_user_or_404(db, current_user_email)
    note_uuid = parse_note_uuid(note_id)
    note = db.query(models.Note).filter(models.Note.id == note_uuid, models.Note.user_id == user.id).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    if note.is_public or not note.uses_protocol:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group-key rotation is only supported for protocol-managed private notes")

    expected_new_version = (note.current_gk_version or 0) + 1
    if payload.new_gk_version != expected_new_version:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect next group-key version")

    validate_key_packets(payload.key_packets, expected_gk_version=payload.new_gk_version)
    packet_recipient_ids = {packet.recipient_user_id for packet in payload.key_packets}
    if user.id not in packet_recipient_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner key packet is required for group-key rotation")
    if payload.revoked_recipient_id and payload.revoked_recipient_id in packet_recipient_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Revoked recipient cannot receive a packet for the new group-key version")

    active_recipient_ids = {
        row.recipient_id
        for row in db.query(models.SharedNote.recipient_id).filter(models.SharedNote.note_id == note_uuid).all()
    }
    if payload.revoked_recipient_id:
        active_recipient_ids.discard(payload.revoked_recipient_id)
    required_ids = set(active_recipient_ids)
    required_ids.add(user.id)
    if packet_recipient_ids != required_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rotation must publish packets for the owner and every remaining recipient")

    # Decode the update token (32 bytes)
    try:
        token_bytes = base64.b64decode(payload.update_token_b64)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid update token") from exc
    if len(token_bytes) != 32:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Update token must be 32 bytes")

    if payload.revoked_recipient_id:
        revoked_share = get_shared_access(db, note_uuid, payload.revoked_recipient_id)
        if revoked_share:
            db.delete(revoked_share)

    # Apply the ciphertext-independent update token to every version's wrapped DEK.
    # enc_dek_new = enc_dek_old ⊕ token  (server never sees DEK or plaintext)
    all_versions = db.query(models.NoteVersion).filter(models.NoteVersion.note_id == note_uuid).all()
    for ver in all_versions:
        old_wrapped = base64.b64decode(ver.wrapped_dek_b64)
        new_wrapped = bytes(a ^ b for a, b in zip(old_wrapped, token_bytes))
        ver.wrapped_dek_b64 = base64.b64encode(new_wrapped).decode()

    for packet in payload.key_packets:
        db.add(
            models.NoteKeyPacket(
                note_id=note_uuid,
                recipient_id=packet.recipient_user_id,
                gk_version=packet.gk_version,
                enc_gk_b64=packet.enc_gk_b64,
                fingerprint_b64=packet.fingerprint_b64,
            )
        )

    note.current_gk_version = payload.new_gk_version
    note.rotation_due = False
    note.last_gk_rotated_at = datetime.utcnow()
    note.updated_at = datetime.utcnow()
    db.commit()
    return {"message": "Group key rotated successfully", "gk_version": note.current_gk_version}


@router.post("/detect-fingerprint", status_code=status.HTTP_200_OK)
async def detect_fingerprint_global(
    payload: schemas.DetectFingerprintRequest,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    """Search ALL notes owned by the current user for a matching fingerprint."""
    user = get_user_or_404(db, current_user_email)

    owned_note_ids = (
        db.query(models.Note.id)
        .filter(models.Note.user_id == user.id, models.Note.uses_protocol == True)
        .subquery()
    )

    row = (
        db.query(models.NoteKeyPacket, models.User, models.Note)
        .join(models.User, models.User.id == models.NoteKeyPacket.recipient_id)
        .join(models.Note, models.Note.id == models.NoteKeyPacket.note_id)
        .filter(
            models.NoteKeyPacket.note_id.in_(owned_note_ids),
            models.NoteKeyPacket.fingerprint_b64 != None,
            models.NoteKeyPacket.fingerprint_b64 == payload.fingerprint_b64,
        )
        .first()
    )

    if row:
        packet, recipient, note = row
        return {
            "found": True,
            "note_id": note.id,
            "note_title": note.title,
            "recipient_id": recipient.id,
            "firstName": recipient.firstName,
            "lastName": recipient.lastName,
            "email": recipient.email,
        }

    return {"found": False}


@router.delete("/{note_id}/share/{recipient_id}", status_code=status.HTTP_400_BAD_REQUEST)
async def unshare_note(
    note_id: str,
    recipient_id: str,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    _ = db
    _ = current_user_email
    _ = note_id
    _ = recipient_id
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Revocation must rotate the group key. Use /notes/{note_id}/rotate-group-key instead.",
    )

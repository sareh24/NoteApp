from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from fastapi import Depends
from app.database import engine, Base, SessionLocal, get_db
from app.routers import auth, notes
from app import models
from app.config import (
    DEFAULT_ADMIN_EMAIL,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_FIRST_NAME,
    DEFAULT_ADMIN_LAST_NAME,
)

# How many days before a note's group key is considered stale and rotation_due is set.
GK_ROTATION_INTERVAL_DAYS = 30

# Create database tables
Base.metadata.create_all(bind=engine)


def ensure_protocol_columns():
    """Backfill protocol columns on existing databases that predate migrations."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.connect() as connection:
        if "users" in existing_tables:
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            if "public_key" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN public_key TEXT"))

        if "notes" in existing_tables:
            note_columns = {column["name"] for column in inspector.get_columns("notes")}
            if "uses_protocol" not in note_columns:
                connection.execute(text("ALTER TABLE notes ADD COLUMN uses_protocol BOOLEAN DEFAULT FALSE"))
            if "current_version" not in note_columns:
                connection.execute(text("ALTER TABLE notes ADD COLUMN current_version INTEGER DEFAULT 0"))
            if "current_gk_version" not in note_columns:
                connection.execute(text("ALTER TABLE notes ADD COLUMN current_gk_version INTEGER DEFAULT 0"))
            if "rotation_due" not in note_columns:
                connection.execute(text("ALTER TABLE notes ADD COLUMN rotation_due BOOLEAN DEFAULT FALSE"))
            if "last_gk_rotated_at" not in note_columns:
                connection.execute(text("ALTER TABLE notes ADD COLUMN last_gk_rotated_at TIMESTAMP"))

        if "note_key_packets" in existing_tables:
            packet_columns = {column["name"] for column in inspector.get_columns("note_key_packets")}
            if "fingerprint_b64" not in packet_columns:
                connection.execute(text("ALTER TABLE note_key_packets ADD COLUMN fingerprint_b64 TEXT"))

        if "shared_notes" in existing_tables:
            shared_columns = {column["name"] for column in inspector.get_columns("shared_notes")}
            if "is_confidential" not in shared_columns:
                connection.execute(text("ALTER TABLE shared_notes ADD COLUMN is_confidential BOOLEAN DEFAULT FALSE"))

        connection.commit()


def ensure_default_admin_user():
    """Create a development admin account once so signup isn't required each run."""
    db = SessionLocal()
    try:
        legacy_admin = db.query(models.User).filter(models.User.email == "admin@noteapp.local").first()
        if legacy_admin:
            legacy_admin.email = DEFAULT_ADMIN_EMAIL
            legacy_admin.is_admin = True
            db.commit()

        admin = db.query(models.User).filter(models.User.email == DEFAULT_ADMIN_EMAIL).first()
        if admin:
            if not admin.is_admin:
                admin.is_admin = True
                db.commit()
            return

        new_admin = models.User(
            firstName=DEFAULT_ADMIN_FIRST_NAME,
            lastName=DEFAULT_ADMIN_LAST_NAME,
            email=DEFAULT_ADMIN_EMAIL,
            password_hash=auth.hash_password(DEFAULT_ADMIN_PASSWORD),
            is_admin=True,
        )
        db.add(new_admin)
        db.commit()
    finally:
        db.close()
def flag_stale_notes_for_rotation():
    """Nightly job: mark protocol notes whose GK is older than GK_ROTATION_INTERVAL_DAYS."""
    db = SessionLocal()
    try:
        threshold = datetime.utcnow() - timedelta(days=GK_ROTATION_INTERVAL_DAYS)
        stale = (
            db.query(models.Note)
            .filter(
                models.Note.uses_protocol == True,
                models.Note.is_public == False,
                models.Note.rotation_due == False,
                (models.Note.last_gk_rotated_at == None)
                | (models.Note.last_gk_rotated_at < threshold),
            )
            .all()
        )
        for note in stale:
            note.rotation_due = True
        if stale:
            db.commit()
    finally:
        db.close()


ensure_protocol_columns()
ensure_default_admin_user()

# Start background scheduler — runs flag_stale_notes_for_rotation every night at 02:00.
_scheduler = BackgroundScheduler()
_scheduler.add_job(flag_stale_notes_for_rotation, "cron", hour=2, minute=0)
_scheduler.start()

app = FastAPI(title="Secure Notes API")

# Add CORS middleware BEFORE routing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (change in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(notes.router)

@app.exception_handler(OperationalError)
async def db_connection_error_handler(request: Request, exc: OperationalError):
    return JSONResponse(
        status_code=503,
        content={"detail": "Service temporarily unavailable. Please try again later."},
    )


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"detail": "Database unreachable"},
        )


@app.get("/")
def root():
    return {"message": "Secure Notes API is running"}
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from app.database import engine, Base, SessionLocal
from app.routers import auth, notes
from app import models
from app.config import (
    DEFAULT_ADMIN_EMAIL,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_FIRST_NAME,
    DEFAULT_ADMIN_LAST_NAME,
)

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
ensure_protocol_columns()
ensure_default_admin_user()

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

@app.get("/")
def root():
    return {"message": "Secure Notes API is running"}
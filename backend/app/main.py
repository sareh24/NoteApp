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


def ensure_user_admin_column():
    """Add users.is_admin for existing SQLite databases without migrations."""
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "is_admin" in user_columns:
        return
    with engine.connect() as connection:
        connection.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
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


ensure_user_admin_column()
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
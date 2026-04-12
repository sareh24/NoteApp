"""
Shared pytest fixtures for the NoteApp backend test suite.

Uses an in-memory SQLite database so no real PostgreSQL instance is needed.
The APScheduler background thread is patched out to keep tests clean and fast.
"""

import os
import uuid
from unittest.mock import patch

# ── Must be set BEFORE any app module is imported ──────────────────────────
os.environ["DATABASE_URL"] = "sqlite:///./test_noteapp.db"

# Prevent dotenv from overriding our DATABASE_URL with the production .env file.
_dotenv_patch = patch("dotenv.load_dotenv")
_dotenv_patch.start()

# Prevent APScheduler from spawning a real background thread during tests.
_sched_patch = patch("apscheduler.schedulers.background.BackgroundScheduler.start")
_sched_patch.start()

from app.main import app  # noqa: E402
from app.database import Base, get_db, engine  # noqa: E402

import pytest
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Database lifecycle ──────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all tables once for the whole test session, then tear down."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ── FastAPI test client ─────────────────────────────────────────────────────

def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    """TestClient with the DB dependency pointing at the SQLite test database."""
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ── Reusable user fixtures ──────────────────────────────────────────────────

@pytest.fixture
def auth_user(client):
    """Register a unique user and return their credentials + JWT token."""
    unique = str(uuid.uuid4())[:8]
    payload = {
        "firstName": "Test",
        "lastName": "User",
        "email": f"user_{unique}@test.com",
        "password": "TestPass123!",
    }
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return {
        "email": payload["email"],
        "password": payload["password"],
        "token": body["access_token"],
        "user": body["user"],
    }


@pytest.fixture
def auth_headers(auth_user):
    """Convenience: Authorization header dict for an authenticated request."""
    return {"Authorization": f"Bearer {auth_user['token']}"}

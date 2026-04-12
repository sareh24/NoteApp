"""
Unit tests — Part 1: Authentication

Covers:
  - POST /auth/register
  - POST /auth/login
  - GET  /auth/users/search
  - PUT  /auth/me/public-key
  - GET  /auth/users/{id}/public-key
"""

import uuid


# ── Helpers ─────────────────────────────────────────────────────────────────

def _unique_email():
    return f"user_{str(uuid.uuid4())[:8]}@test.com"


def _register(client, email=None, password="TestPass123!",
              first="Alice", last="Smith"):
    email = email or _unique_email()
    resp = client.post("/auth/register", json={
        "firstName": first,
        "lastName": last,
        "email": email,
        "password": password,
    })
    return resp, email


# ── Registration ─────────────────────────────────────────────────────────────

class TestRegister:

    def test_success_returns_token_and_user(self, client):
        resp, email = _register(client)
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["user"]["email"] == email
        assert body["user"]["firstName"] == "Alice"

    def test_token_is_valid_jwt(self, client):
        resp, _ = _register(client)
        token = resp.json()["access_token"]
        # A JWT has exactly 3 dot-separated parts
        assert len(token.split(".")) == 3

    def test_duplicate_email_returns_400(self, client):
        email = _unique_email()
        _register(client, email=email)
        resp2, _ = _register(client, email=email)
        assert resp2.status_code == 400
        assert "already registered" in resp2.json()["detail"].lower()

    def test_invalid_email_returns_422(self, client):
        resp = client.post("/auth/register", json={
            "firstName": "X",
            "lastName": "Y",
            "email": "not-an-email",
            "password": "TestPass123!",
        })
        assert resp.status_code == 422

    def test_missing_required_fields_returns_422(self, client):
        resp = client.post("/auth/register", json={"email": _unique_email()})
        assert resp.status_code == 422

    def test_response_does_not_expose_password_hash(self, client):
        resp, _ = _register(client)
        body = str(resp.json())
        assert "password_hash" not in body
        assert "hash" not in body


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_success_returns_token(self, client):
        email = _unique_email()
        _register(client, email=email, password="LoginPass1!")
        resp = client.post("/auth/login", json={
            "email": email,
            "password": "LoginPass1!",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_returns_correct_user(self, client):
        email = _unique_email()
        _register(client, email=email, first="Bob", last="Jones")
        resp = client.post("/auth/login", json={
            "email": email,
            "password": "TestPass123!",
        })
        user = resp.json()["user"]
        assert user["email"] == email
        assert user["firstName"] == "Bob"

    def test_wrong_password_returns_401(self, client):
        email = _unique_email()
        _register(client, email=email, password="CorrectPass1!")
        resp = client.post("/auth/login", json={
            "email": email,
            "password": "WrongPass999!",
        })
        assert resp.status_code == 401

    def test_unknown_email_returns_401(self, client):
        resp = client.post("/auth/login", json={
            "email": "nobody@nowhere.com",
            "password": "AnyPass1!",
        })
        assert resp.status_code == 401

    def test_login_token_is_valid_jwt(self, client):
        email = _unique_email()
        _register(client, email=email)
        resp = client.post("/auth/login", json={
            "email": email,
            "password": "TestPass123!",
        })
        token = resp.json()["access_token"]
        assert len(token.split(".")) == 3


# ── User search ───────────────────────────────────────────────────────────────

class TestUserSearch:

    def test_requires_authentication(self, client):
        resp = client.get("/auth/users/search?q=test")
        assert resp.status_code == 401

    def test_query_too_short_returns_empty_list(self, client, auth_headers):
        resp = client.get("/auth/users/search?q=a", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_finds_user_by_first_name(self, client, auth_user, auth_headers):
        unique = str(uuid.uuid4())[:8]
        _register(client, email=f"searchme_{unique}@test.com",
                  first="Findable", last="Person")
        resp = client.get("/auth/users/search?q=Findable", headers=auth_headers)
        assert resp.status_code == 200
        results = resp.json()
        assert any(u["firstName"] == "Findable" for u in results)

    def test_finds_user_by_email(self, client, auth_headers):
        unique = str(uuid.uuid4())[:8]
        email = f"searchbyemail_{unique}@test.com"
        _register(client, email=email, first="Email", last="Search")
        resp = client.get(
            f"/auth/users/search?q=searchbyemail_{unique}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert any(u["email"] == email for u in resp.json())

    def test_caller_excluded_from_results(self, client, auth_user, auth_headers):
        resp = client.get(
            f"/auth/users/search?q={auth_user['user']['firstName']}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        emails = [u["email"] for u in resp.json()]
        assert auth_user["email"] not in emails

    def test_result_includes_has_public_key_field(self, client, auth_headers):
        unique = str(uuid.uuid4())[:8]
        _register(client, email=f"hasPkField_{unique}@test.com",
                  first=f"HasPk{unique}", last="Test")
        resp = client.get(
            f"/auth/users/search?q=HasPk{unique}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) >= 1
        assert "has_public_key" in results[0]


# ── Public key management ─────────────────────────────────────────────────────

class TestPublicKey:

    def test_upsert_public_key(self, client, auth_headers):
        resp = client.put(
            "/auth/me/public-key",
            json={"public_key": "base64encodedpublickeyXYZ=="},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["public_key"] == "base64encodedpublickeyXYZ=="

    def test_upsert_requires_auth(self, client):
        resp = client.put(
            "/auth/me/public-key",
            json={"public_key": "somekey"},
        )
        assert resp.status_code == 401

    def test_fetch_published_key(self, client, auth_user, auth_headers):
        # Publish a key
        test_key = "fetchable_public_key_abc123=="
        client.put(
            "/auth/me/public-key",
            json={"public_key": test_key},
            headers=auth_headers,
        )
        user_id = auth_user["user"]["id"]
        resp = client.get(
            f"/auth/users/{user_id}/public-key",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["public_key"] == test_key

    def test_fetch_key_for_user_without_key_returns_404(self, client, auth_headers):
        # Register a user who never publishes a key
        unique = str(uuid.uuid4())[:8]
        reg_resp, _ = _register(client, email=f"nokey_{unique}@test.com")
        no_key_user_id = reg_resp.json()["user"]["id"]

        resp = client.get(
            f"/auth/users/{no_key_user_id}/public-key",
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_fetch_key_invalid_uuid_returns_400(self, client, auth_headers):
        resp = client.get(
            "/auth/users/not-a-valid-uuid/public-key",
            headers=auth_headers,
        )
        assert resp.status_code == 400

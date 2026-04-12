"""
Unit tests — Part 2: Note CRUD

Covers:
  - POST   /notes/           create public note
  - POST   /notes/           create private protocol note
  - GET    /notes/           list own notes
  - GET    /notes/public     public feed
  - GET    /notes/shared     shared-with-me list
  - GET    /notes/{id}       fetch single note
  - PUT    /notes/{id}       update note
  - DELETE /notes/{id}       delete note
"""

import uuid
import base64


# ── Helpers ──────────────────────────────────────────────────────────────────

def _unique_email():
    return f"notes_{str(uuid.uuid4())[:8]}@test.com"


def _register_and_login(client, first="Note", last="Tester"):
    email = _unique_email()
    resp = client.post("/auth/register", json={
        "firstName": first,
        "lastName": last,
        "email": email,
        "password": "NotePass123!",
    })
    assert resp.status_code == 200
    body = resp.json()
    token = body["access_token"]
    return token, body["user"], {"Authorization": f"Bearer {token}"}


def _b64(n_bytes: int = 32) -> str:
    """Return a random base64-encoded string of n_bytes."""
    return base64.b64encode(bytes(range(n_bytes % 256)) * (n_bytes // 256 + 1))[:n_bytes].decode()


def _make_version_payload(version: int = 1, gk_version: int = 1) -> dict:
    """Minimal encrypted version payload (fake ciphertext — backend stores, not decrypts)."""
    return {
        "version": version,
        "gk_version": gk_version,
        "content_nonce_b64": _b64(24),
        "content_ciphertext_b64": _b64(48),
        "wrapped_dek_b64": _b64(32),
    }


def _make_key_packet(user_id: str, gk_version: int = 1) -> dict:
    return {
        "recipient_user_id": user_id,
        "gk_version": gk_version,
        "enc_gk_b64": _b64(48),
    }


def _create_public_note(client, headers, title="Public Note", content="<p>Hello</p>"):
    resp = client.post("/notes/", json={
        "title": title,
        "content": content,
        "is_public": True,
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_private_note(client, headers, user_id: str, title="Private Note"):
    resp = client.post("/notes/", json={
        "title": title,
        "is_public": False,
        "initial_version": _make_version_payload(),
        "key_packets": [_make_key_packet(user_id)],
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── Create public note ────────────────────────────────────────────────────────

class TestCreatePublicNote:

    def test_success_returns_201(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "title": "My Note",
            "content": "<p>Content</p>",
            "is_public": True,
        }, headers=headers)
        assert resp.status_code == 201

    def test_response_contains_expected_fields(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        assert "id" in note
        assert note["title"] == "Public Note"
        assert note["is_public"] is True
        assert note["uses_protocol"] is False
        assert note["is_owner"] is True

    def test_requires_authentication(self, client):
        resp = client.post("/notes/", json={
            "title": "Unauth Note",
            "content": "<p>x</p>",
            "is_public": True,
        })
        assert resp.status_code == 401

    def test_public_note_without_content_returns_400(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "title": "Empty",
            "is_public": True,
        }, headers=headers)
        assert resp.status_code == 400

    def test_default_title_when_omitted(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "content": "<p>No title</p>",
            "is_public": True,
        }, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["title"] == "Untitled Note"


# ── Create private protocol note ─────────────────────────────────────────────

class TestCreatePrivateNote:

    def test_success_returns_201(self, client):
        _, user, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "title": "Secret",
            "is_public": False,
            "initial_version": _make_version_payload(),
            "key_packets": [_make_key_packet(user["id"])],
        }, headers=headers)
        assert resp.status_code == 201

    def test_uses_protocol_flag_is_true(self, client):
        _, user, headers = _register_and_login(client)
        note = _create_private_note(client, headers, user["id"])
        assert note["uses_protocol"] is True
        assert note["is_public"] is False

    def test_content_is_null_in_response(self, client):
        """Backend must not return plaintext content for protocol notes."""
        _, user, headers = _register_and_login(client)
        note = _create_private_note(client, headers, user["id"])
        assert note["content"] is None

    def test_missing_initial_version_returns_400(self, client):
        _, user, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "is_public": False,
            "key_packets": [_make_key_packet(user["id"])],
        }, headers=headers)
        assert resp.status_code == 400

    def test_missing_key_packets_returns_400(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "is_public": False,
            "initial_version": _make_version_payload(),
            "key_packets": [],
        }, headers=headers)
        assert resp.status_code == 400

    def test_missing_owner_key_packet_returns_400(self, client):
        """Key packets must include the owner — a different user's ID is not enough."""
        _, _, headers = _register_and_login(client)
        other_id = str(uuid.uuid4())
        resp = client.post("/notes/", json={
            "is_public": False,
            "initial_version": _make_version_payload(),
            "key_packets": [_make_key_packet(other_id)],
        }, headers=headers)
        assert resp.status_code == 400

    def test_wrong_initial_version_numbers_return_400(self, client):
        _, user, headers = _register_and_login(client)
        resp = client.post("/notes/", json={
            "is_public": False,
            "initial_version": _make_version_payload(version=2, gk_version=1),
            "key_packets": [_make_key_packet(user["id"])],
        }, headers=headers)
        assert resp.status_code == 400


# ── List notes ────────────────────────────────────────────────────────────────

class TestListNotes:

    def test_requires_authentication(self, client):
        resp = client.get("/notes/")
        assert resp.status_code == 401

    def test_returns_own_notes(self, client):
        _, _, headers = _register_and_login(client)
        _create_public_note(client, headers, title="Mine")
        resp = client.get("/notes/", headers=headers)
        assert resp.status_code == 200
        titles = [n["title"] for n in resp.json()]
        assert "Mine" in titles

    def test_does_not_return_other_users_private_notes(self, client):
        _, user_a, headers_a = _register_and_login(client)
        _, _, headers_b = _register_and_login(client)
        _create_private_note(client, headers_a, user_a["id"], title="User A Secret")
        resp = client.get("/notes/", headers=headers_b)
        titles = [n["title"] for n in resp.json()]
        assert "User A Secret" not in titles

    def test_returns_list_type(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.get("/notes/", headers=headers)
        assert isinstance(resp.json(), list)


# ── Public feed ───────────────────────────────────────────────────────────────

class TestPublicFeed:

    def test_public_notes_visible_without_auth(self, client):
        _, _, headers = _register_and_login(client)
        unique_title = f"PublicFeed_{str(uuid.uuid4())[:8]}"
        _create_public_note(client, headers, title=unique_title)
        resp = client.get("/notes/public")
        assert resp.status_code == 200
        titles = [n["title"] for n in resp.json()]
        assert unique_title in titles

    def test_private_notes_not_in_public_feed(self, client):
        _, user, headers = _register_and_login(client)
        private_title = f"HiddenPrivate_{str(uuid.uuid4())[:8]}"
        _create_private_note(client, headers, user["id"], title=private_title)
        resp = client.get("/notes/public")
        titles = [n["title"] for n in resp.json()]
        assert private_title not in titles


# ── Fetch single note ─────────────────────────────────────────────────────────

class TestGetNote:

    def test_owner_can_fetch_own_note(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.get(f"/notes/{note['id']}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == note["id"]

    def test_nonexistent_note_returns_404(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.get(f"/notes/{uuid.uuid4()}", headers=headers)
        assert resp.status_code == 404

    def test_invalid_uuid_returns_400(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.get("/notes/not-a-uuid", headers=headers)
        assert resp.status_code == 400

    def test_unauthenticated_request_returns_401(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.get(f"/notes/{note['id']}")
        assert resp.status_code == 401

    def test_other_user_cannot_fetch_private_note(self, client):
        _, user_a, headers_a = _register_and_login(client)
        _, _, headers_b = _register_and_login(client)
        note = _create_private_note(client, headers_a, user_a["id"])
        resp = client.get(f"/notes/{note['id']}", headers=headers_b)
        assert resp.status_code in (403, 404)

    def test_public_note_visible_to_any_authenticated_user(self, client):
        _, _, headers_a = _register_and_login(client)
        _, _, headers_b = _register_and_login(client)
        note = _create_public_note(client, headers_a)
        resp = client.get(f"/notes/{note['id']}", headers=headers_b)
        assert resp.status_code == 200


# ── Update note ───────────────────────────────────────────────────────────────

class TestUpdateNote:

    def test_update_public_note_title(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.put(f"/notes/{note['id']}",
                          json={"title": "Updated Title"},
                          headers=headers)
        assert resp.status_code == 200
        assert resp.json()["title"] == "Updated Title"

    def test_update_public_note_content(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.put(f"/notes/{note['id']}",
                          json={"content": "<p>New content</p>"},
                          headers=headers)
        assert resp.status_code == 200
        assert resp.json()["content"] == "<p>New content</p>"

    def test_update_private_protocol_note_requires_next_version(self, client):
        _, user, headers = _register_and_login(client)
        note = _create_private_note(client, headers, user["id"])
        resp = client.put(f"/notes/{note['id']}",
                          json={"title": "New Title"},
                          headers=headers)
        assert resp.status_code == 400

    def test_update_private_note_with_correct_version(self, client):
        _, user, headers = _register_and_login(client)
        note = _create_private_note(client, headers, user["id"])
        next_v = _make_version_payload(version=2, gk_version=1)
        resp = client.put(f"/notes/{note['id']}",
                          json={"title": "V2 Title", "next_version": next_v},
                          headers=headers)
        assert resp.status_code == 200
        assert resp.json()["current_version"] == 2

    def test_update_private_note_wrong_version_returns_400(self, client):
        _, user, headers = _register_and_login(client)
        note = _create_private_note(client, headers, user["id"])
        wrong_v = _make_version_payload(version=99, gk_version=1)
        resp = client.put(f"/notes/{note['id']}",
                          json={"next_version": wrong_v},
                          headers=headers)
        assert resp.status_code == 400

    def test_other_user_cannot_update_note(self, client):
        _, _, headers_a = _register_and_login(client)
        _, _, headers_b = _register_and_login(client)
        note = _create_public_note(client, headers_a)
        resp = client.put(f"/notes/{note['id']}",
                          json={"title": "Hijacked"},
                          headers=headers_b)
        assert resp.status_code in (403, 404)

    def test_unauthenticated_update_returns_401(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.put(f"/notes/{note['id']}", json={"title": "X"})
        assert resp.status_code == 401


# ── Delete note ───────────────────────────────────────────────────────────────

class TestDeleteNote:

    def test_owner_can_delete_note(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.delete(f"/notes/{note['id']}", headers=headers)
        assert resp.status_code == 204

    def test_deleted_note_returns_404_on_fetch(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        client.delete(f"/notes/{note['id']}", headers=headers)
        resp = client.get(f"/notes/{note['id']}", headers=headers)
        assert resp.status_code == 404

    def test_other_user_cannot_delete_note(self, client):
        _, _, headers_a = _register_and_login(client)
        _, _, headers_b = _register_and_login(client)
        note = _create_public_note(client, headers_a)
        resp = client.delete(f"/notes/{note['id']}", headers=headers_b)
        assert resp.status_code == 404

    def test_unauthenticated_delete_returns_401(self, client):
        _, _, headers = _register_and_login(client)
        note = _create_public_note(client, headers)
        resp = client.delete(f"/notes/{note['id']}")
        assert resp.status_code == 401

    def test_delete_nonexistent_note_returns_404(self, client):
        _, _, headers = _register_and_login(client)
        resp = client.delete(f"/notes/{uuid.uuid4()}", headers=headers)
        assert resp.status_code == 404

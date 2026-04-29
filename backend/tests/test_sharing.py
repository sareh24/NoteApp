"""
Unit tests — Part 3: Sharing, Fingerprint Detection & Group-Key Rotation

Covers:
  - POST   /notes/{id}/share              share a note with a recipient
  - GET    /notes/{id}/shares             list who a note is shared with
  - GET    /notes/shared                  shared-with-me list
  - POST   /notes/detect-fingerprint      global fingerprint detection
  - POST   /notes/{id}/rotate-group-key   group-key rotation (incl. revocation)
"""

import uuid
import base64


# ── Helpers ───────────────────────────────────────────────────────────────────

def _unique_email():
    return f"share_{str(uuid.uuid4())[:8]}@test.com"


def _register_and_login(client, first="Share", last="Tester"):
    email = _unique_email()
    resp = client.post("/auth/register", json={
        "firstName": first,
        "lastName": last,
        "email": email,
        "password": "SharePass123!",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return body["access_token"], body["user"], {"Authorization": f"Bearer {body['access_token']}"}


def _b64(n_bytes: int = 32) -> str:
    raw = (bytes(range(256)) * (n_bytes // 256 + 1))[:n_bytes]
    return base64.b64encode(raw).decode()


def _make_version_payload(version: int = 1, gk_version: int = 1) -> dict:
    return {
        "version": version,
        "gk_version": gk_version,
        "content_nonce_b64": _b64(24),
        "content_ciphertext_b64": _b64(48),
        "wrapped_dek_b64": _b64(32),
    }


def _make_key_packet(user_id: str, gk_version: int = 1, fingerprint: str = None) -> dict:
    pkt = {
        "recipient_user_id": user_id,
        "gk_version": gk_version,
        "enc_gk_b64": _b64(48),
    }
    if fingerprint is not None:
        pkt["fingerprint_b64"] = fingerprint
    return pkt


def _create_private_note(client, headers, owner_id: str, title="Private Note"):
    resp = client.post("/notes/", json={
        "title": title,
        "is_public": False,
        "initial_version": _make_version_payload(),
        "key_packets": [_make_key_packet(owner_id)],
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _share_note(client, headers, note_id: str, recipient_id: str,
                gk_version: int = 1, fingerprint: str = None, can_edit: bool = False):
    body = {
        "recipient_id": recipient_id,
        "can_edit": can_edit,
        "gk_version": gk_version,
        "enc_gk_b64": _b64(48),
    }
    if fingerprint is not None:
        body["fingerprint_b64"] = fingerprint
    return client.post(f"/notes/{note_id}/share", json=body, headers=headers)


# ── Share note ────────────────────────────────────────────────────────────────

class TestShareNote:

    def test_owner_can_share_note(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, owner_h, note["id"], recip["id"])
        assert resp.status_code == 200, resp.text

    def test_share_returns_message(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, owner_h, note["id"], recip["id"])
        assert "message" in resp.json()

    def test_non_owner_cannot_share(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, other, other_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, other_h, note["id"], recip["id"])
        assert resp.status_code == 404

    def test_cannot_share_public_note(self, client):
        _, _, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        pub = client.post("/notes/", json={
            "title": "Public",
            "content": "<p>Hi</p>",
            "is_public": True,
        }, headers=owner_h)
        assert pub.status_code == 201
        resp = _share_note(client, owner_h, pub.json()["id"], recip["id"])
        assert resp.status_code == 400

    def test_cannot_share_with_self(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, owner_h, note["id"], owner["id"])
        assert resp.status_code == 400

    def test_share_with_nonexistent_user_returns_404(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, owner_h, note["id"], str(uuid.uuid4()))
        assert resp.status_code == 404

    def test_unauthenticated_share_returns_401(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, {}, note["id"], recip["id"])
        assert resp.status_code == 401

    def test_wrong_gk_version_returns_400(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = _share_note(client, owner_h, note["id"], recip["id"], gk_version=99)
        assert resp.status_code == 400


# ── List shares ───────────────────────────────────────────────────────────────

class TestListShares:

    def test_owner_can_list_shares(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip["id"])
        resp = client.get(f"/notes/{note['id']}/shares", headers=owner_h)
        assert resp.status_code == 200
        ids = [r["recipient_id"] for r in resp.json()]
        assert recip["id"] in ids

    def test_shares_include_expected_fields(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip["id"])
        resp = client.get(f"/notes/{note['id']}/shares", headers=owner_h)
        share = resp.json()[0]
        for field in ("recipient_id", "firstName", "lastName", "email", "can_edit", "shared_at"):
            assert field in share, f"missing field: {field}"

    def test_non_owner_cannot_list_shares(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, other, other_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = client.get(f"/notes/{note['id']}/shares", headers=other_h)
        assert resp.status_code == 403

    def test_unauthenticated_returns_401(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = client.get(f"/notes/{note['id']}/shares")
        assert resp.status_code == 401

    def test_empty_list_before_any_share(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        resp = client.get(f"/notes/{note['id']}/shares", headers=owner_h)
        assert resp.status_code == 200
        assert resp.json() == []


# ── Shared-with-me list ───────────────────────────────────────────────────────

class TestSharedWithMe:

    def test_recipient_sees_shared_note(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, recip_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"], title="Shared To Recip")
        _share_note(client, owner_h, note["id"], recip["id"])
        resp = client.get("/notes/shared", headers=recip_h)
        assert resp.status_code == 200
        ids = [n["id"] for n in resp.json()]
        assert note["id"] in ids

    def test_owner_does_not_see_own_note_in_shared(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip["id"])
        resp = client.get("/notes/shared", headers=owner_h)
        ids = [n["id"] for n in resp.json()]
        assert note["id"] not in ids

    def test_unshared_note_not_in_shared_list(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, other, other_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"], title="Not Shared")
        resp = client.get("/notes/shared", headers=other_h)
        ids = [n["id"] for n in resp.json()]
        assert note["id"] not in ids

    def test_unauthenticated_returns_401(self, client):
        resp = client.get("/notes/shared")
        assert resp.status_code == 401


# ── Detect fingerprint ────────────────────────────────────────────────────────

class TestDetectFingerprint:

    def _share_with_fingerprint(self, client, owner_h, note_id, recip_id, fingerprint):
        resp = client.post(f"/notes/{note_id}/share", json={
            "recipient_id": recip_id,
            "can_edit": False,
            "gk_version": 1,
            "enc_gk_b64": _b64(48),
            "fingerprint_b64": fingerprint,
        }, headers=owner_h)
        assert resp.status_code == 200, resp.text

    def test_found_matching_fingerprint(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        fp = _b64(16)
        self._share_with_fingerprint(client, owner_h, note["id"], recip["id"], fp)
        resp = client.post("/notes/detect-fingerprint",
                           json={"fingerprint_b64": fp},
                           headers=owner_h)
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert data["note_id"] == note["id"]
        assert data["firstName"] == recip["firstName"]

    def test_not_found_returns_found_false(self, client):
        _, owner, owner_h = _register_and_login(client)
        resp = client.post("/notes/detect-fingerprint",
                           json={"fingerprint_b64": _b64(16)},
                           headers=owner_h)
        assert resp.status_code == 200
        assert resp.json()["found"] is False

    def test_owner_cannot_detect_in_other_users_notes(self, client):
        """Owner A's fingerprint detection should not find notes belonging to owner B."""
        _, owner_a, owner_a_h = _register_and_login(client)
        _, owner_b, owner_b_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note_b = _create_private_note(client, owner_b_h, owner_b["id"])
        fp = _b64(16)
        self._share_with_fingerprint(client, owner_b_h, note_b["id"], recip["id"], fp)
        # Owner A searches — should not find it
        resp = client.post("/notes/detect-fingerprint",
                           json={"fingerprint_b64": fp},
                           headers=owner_a_h)
        assert resp.json()["found"] is False

    def test_response_includes_recipient_info_when_found(self, client):
        _, owner, owner_h = _register_and_login(client, first="DetOwner", last="O")
        _, recip, _ = _register_and_login(client, first="Leaker", last="L")
        note = _create_private_note(client, owner_h, owner["id"])
        fp = _b64(16)
        self._share_with_fingerprint(client, owner_h, note["id"], recip["id"], fp)
        data = client.post("/notes/detect-fingerprint",
                           json={"fingerprint_b64": fp},
                           headers=owner_h).json()
        for field in ("note_id", "note_title", "recipient_id", "firstName", "lastName", "email"):
            assert field in data, f"missing field: {field}"

    def test_unauthenticated_returns_401(self, client):
        resp = client.post("/notes/detect-fingerprint",
                           json={"fingerprint_b64": _b64(16)})
        assert resp.status_code == 401


# ── Group-key rotation ────────────────────────────────────────────────────────

class TestRotateGroupKey:

    def _rotation_payload(self, new_gk_version: int, owner_id: str,
                          extra_recipients: list = None, revoked_id: str = None) -> dict:
        packets = [_make_key_packet(owner_id, gk_version=new_gk_version)]
        for rid in (extra_recipients or []):
            packets.append(_make_key_packet(rid, gk_version=new_gk_version))
        payload = {
            "new_gk_version": new_gk_version,
            "update_token_b64": _b64(32),
            "key_packets": packets,
        }
        if revoked_id:
            payload["revoked_recipient_id"] = revoked_id
        return payload

    def test_owner_can_rotate(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=2, owner_id=owner["id"])
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 200, resp.text
        assert resp.json()["gk_version"] == 2

    def test_rotation_increments_gk_version(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=2, owner_id=owner["id"])
        client.post(f"/notes/{note['id']}/rotate-group-key", json=payload, headers=owner_h)
        note_resp = client.get(f"/notes/{note['id']}", headers=owner_h)
        assert note_resp.json()["current_gk_version"] == 2

    def test_wrong_new_gk_version_returns_400(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=99, owner_id=owner["id"])
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 400

    def test_missing_owner_packet_returns_400(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip["id"])
        # Only include recipient's packet — omit the owner's
        payload = {
            "new_gk_version": 2,
            "update_token_b64": _b64(32),
            "key_packets": [_make_key_packet(recip["id"], gk_version=2)],
        }
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 400

    def test_revocation_removes_recipient_access(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, recip_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip["id"])

        # Rotate and revoke recip — only owner packet in new rotation
        payload = {
            "new_gk_version": 2,
            "update_token_b64": _b64(32),
            "revoked_recipient_id": recip["id"],
            "key_packets": [_make_key_packet(owner["id"], gk_version=2)],
        }
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 200

        # Revoked recipient should no longer have access
        access_resp = client.get(f"/notes/{note['id']}", headers=recip_h)
        assert access_resp.status_code in (403, 404)

    def test_revoked_recipient_must_not_receive_new_packet(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, recip, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip["id"])

        # Try to revoke but still include a packet for them
        payload = {
            "new_gk_version": 2,
            "update_token_b64": _b64(32),
            "revoked_recipient_id": recip["id"],
            "key_packets": [
                _make_key_packet(owner["id"], gk_version=2),
                _make_key_packet(recip["id"], gk_version=2),  # should be rejected
            ],
        }
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 400

    def test_non_owner_cannot_rotate(self, client):
        _, owner, owner_h = _register_and_login(client)
        _, other, other_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=2, owner_id=owner["id"])
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=other_h)
        assert resp.status_code == 404

    def test_unauthenticated_returns_401(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=2, owner_id=owner["id"])
        resp = client.post(f"/notes/{note['id']}/rotate-group-key", json=payload)
        assert resp.status_code == 401

    def test_rotation_resets_rotation_due_flag(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=2, owner_id=owner["id"])
        client.post(f"/notes/{note['id']}/rotate-group-key", json=payload, headers=owner_h)
        note_resp = client.get(f"/notes/{note['id']}", headers=owner_h)
        assert note_resp.json()["rotation_due"] is False

    def test_invalid_update_token_returns_400(self, client):
        _, owner, owner_h = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        payload = self._rotation_payload(new_gk_version=2, owner_id=owner["id"])
        payload["update_token_b64"] = "!!!not-base64!!!"
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 400

    def test_rotation_with_all_active_recipients_included(self, client):
        """Packets must cover owner + all remaining recipients exactly."""
        _, owner, owner_h = _register_and_login(client)
        _, recip_a, _ = _register_and_login(client)
        _, recip_b, _ = _register_and_login(client)
        note = _create_private_note(client, owner_h, owner["id"])
        _share_note(client, owner_h, note["id"], recip_a["id"])
        _share_note(client, owner_h, note["id"], recip_b["id"])

        payload = {
            "new_gk_version": 2,
            "update_token_b64": _b64(32),
            "key_packets": [
                _make_key_packet(owner["id"], gk_version=2),
                _make_key_packet(recip_a["id"], gk_version=2),
                _make_key_packet(recip_b["id"], gk_version=2),
            ],
        }
        resp = client.post(f"/notes/{note['id']}/rotate-group-key",
                           json=payload, headers=owner_h)
        assert resp.status_code == 200

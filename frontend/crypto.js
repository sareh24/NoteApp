const LEGACY_CONTENT_PREFIX = "enc:v1:";
const ENVELOPE_CONTENT_PREFIX = "enc:v2:";
const KEY_MAP_STORAGE_ITEM = "note_app_kek_map_v1";
const KEY_OWNER_ITEM = "note_app_key_owner";
const PBKDF2_ITERATIONS = 210000;
const CURRENT_KEY_VERSION = "kek-v2";
const LEGACY_KEY_VERSION = "legacy-email-salt";

function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// Generate AES key from password and salt.
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function deriveVersionedKey(password, email, keyVersion) {
    const normalizedEmail = String(email || "").toLowerCase();
    const saltText = `${normalizedEmail}|${keyVersion}`;
    const salt = new TextEncoder().encode(saltText);
    return deriveKey(password, salt);
}

async function deriveLegacyKey(password, email) {
    const normalizedEmail = String(email || "").toLowerCase();
    const salt = new TextEncoder().encode(normalizedEmail);
    return deriveKey(password, salt);
}

async function exportKeyBase64(key) {
    const raw = await window.crypto.subtle.exportKey("raw", key);
    return bytesToBase64(new Uint8Array(raw));
}

async function importKeyBase64(base64) {
    const raw = base64ToBytes(base64);
    return window.crypto.subtle.importKey(
        "raw",
        raw,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function deriveAndStoreKeyFromCredentials(password, email) {
    const normalizedEmail = String(email || "").toLowerCase();

    const currentKek = await deriveVersionedKey(password, normalizedEmail, CURRENT_KEY_VERSION);
    const legacyKek = await deriveLegacyKey(password, normalizedEmail);

    const exportedMap = {
        [CURRENT_KEY_VERSION]: await exportKeyBase64(currentKek),
        [LEGACY_KEY_VERSION]: await exportKeyBase64(legacyKek)
    };

    sessionStorage.setItem(KEY_MAP_STORAGE_ITEM, JSON.stringify(exportedMap));
    sessionStorage.setItem(KEY_OWNER_ITEM, normalizedEmail);
    return currentKek;
}

async function loadStoredKeyForUser(email, keyVersion = CURRENT_KEY_VERSION) {
    const encodedMap = sessionStorage.getItem(KEY_MAP_STORAGE_ITEM);
    const owner = sessionStorage.getItem(KEY_OWNER_ITEM);
    const normalizedEmail = String(email || "").toLowerCase();

    if (!encodedMap || !owner || owner !== normalizedEmail) {
        return null;
    }

    let parsed;
    try {
        parsed = JSON.parse(encodedMap);
    } catch (_err) {
        return null;
    }

    const encoded = parsed[keyVersion];
    if (!encoded) {
        return null;
    }

    return importKeyBase64(encoded);
}

function clearStoredKey() {
    sessionStorage.removeItem(KEY_MAP_STORAGE_ITEM);
    sessionStorage.removeItem(KEY_OWNER_ITEM);
}

function isEncryptedPayload(value) {
    return typeof value === "string" && (
        value.startsWith(LEGACY_CONTENT_PREFIX) || value.startsWith(ENVELOPE_CONTENT_PREFIX)
    );
}

function wrapEncryptedPayload(base64Ciphertext) {
    return `${ENVELOPE_CONTENT_PREFIX}${base64Ciphertext}`;
}

function unwrapEncryptedPayload(value) {
    if (typeof value !== "string") {
        return value;
    }
    if (value.startsWith(ENVELOPE_CONTENT_PREFIX)) {
        return value.slice(ENVELOPE_CONTENT_PREFIX.length);
    }
    if (value.startsWith(LEGACY_CONTENT_PREFIX)) {
        return value.slice(LEGACY_CONTENT_PREFIX.length);
    }
    return value;
}

function isEnvelopeEncryptedPayload(value) {
    return typeof value === "string" && value.startsWith(ENVELOPE_CONTENT_PREFIX);
}

function isLegacyEncryptedPayload(value) {
    return typeof value === "string" && value.startsWith(LEGACY_CONTENT_PREFIX);
}

// Encrypt note content.
async function encryptNote(content, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return bytesToBase64(combined);
}

// Decrypt note content.
async function decryptNote(encryptedBase64, key) {
    const combined = base64ToBytes(encryptedBase64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

async function generateDataEncryptionKey() {
    return window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function wrapDataEncryptionKey(dek, kek) {
    const rawDek = await window.crypto.subtle.exportKey("raw", dek);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        kek,
        rawDek
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return bytesToBase64(combined);
}

async function unwrapDataEncryptionKey(wrappedDekBase64, kek) {
    const combined = base64ToBytes(wrappedDekBase64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const rawDek = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        kek,
        ciphertext
    );

    return window.crypto.subtle.importKey(
        "raw",
        rawDek,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptPrivateNoteForStorage(plaintextContent, ownerEmail) {
    const kek = await loadStoredKeyForUser(ownerEmail, CURRENT_KEY_VERSION);
    if (!kek) {
        throw new Error("Encryption key is not available for current user session.");
    }

    const dek = await generateDataEncryptionKey();
    const ciphertext = await encryptNote(plaintextContent, dek);
    const encryptedDek = await wrapDataEncryptionKey(dek, kek);

    return {
        content: wrapEncryptedPayload(ciphertext),
        encryptedDek,
        keyVersion: CURRENT_KEY_VERSION
    };
}

async function decryptPrivateNoteFromRecord(noteRecord, ownerEmail) {
    if (!noteRecord || noteRecord.is_public) {
        return noteRecord && typeof noteRecord.content === "string" ? noteRecord.content : "";
    }

    const rawContent = noteRecord.content || "";
    if (!isEncryptedPayload(rawContent)) {
        // Legacy plaintext private note.
        return rawContent;
    }

    if (isLegacyEncryptedPayload(rawContent)) {
        const legacyKey = await loadStoredKeyForUser(ownerEmail, LEGACY_KEY_VERSION);
        if (!legacyKey) {
            throw new Error("Legacy note key is missing. Please log in again.");
        }
        return decryptNote(unwrapEncryptedPayload(rawContent), legacyKey);
    }

    // Envelope-encrypted private note.
    const keyVersion = noteRecord.key_version || CURRENT_KEY_VERSION;
    const encryptedDek = noteRecord.encrypted_dek;
    if (!encryptedDek) {
        throw new Error("Encrypted private note is missing wrapped key metadata.");
    }

    const kek = await loadStoredKeyForUser(ownerEmail, keyVersion);
    if (!kek) {
        throw new Error("Note key version is not available in session. Please log in again.");
    }

    const dek = await unwrapDataEncryptionKey(encryptedDek, kek);
    return decryptNote(unwrapEncryptedPayload(rawContent), dek);
}

// Allow Jest (Node.js) to import the pure, side-effect-free helpers for unit testing.
// The crypto-API functions are excluded here — they require Web Crypto and a browser context.
if (typeof module !== "undefined") {
    module.exports = {
        bytesToBase64,
        base64ToBytes,
        isEncryptedPayload,
        wrapEncryptedPayload,
        unwrapEncryptedPayload,
        isEnvelopeEncryptedPayload,
        isLegacyEncryptedPayload,
        LEGACY_CONTENT_PREFIX,
        ENVELOPE_CONTENT_PREFIX,
    };
}
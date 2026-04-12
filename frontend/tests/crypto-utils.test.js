"use strict";
/**
 * Unit tests for the pure utility helpers in crypto.js
 *
 * Covers:
 *   - bytesToBase64 / base64ToBytes  — binary ↔ base64 round-trip
 *   - isEncryptedPayload             — detects both legacy and envelope prefixes
 *   - wrapEncryptedPayload           — adds envelope prefix
 *   - unwrapEncryptedPayload         — strips either prefix
 *   - isEnvelopeEncryptedPayload     — detects only the envelope prefix
 *   - isLegacyEncryptedPayload       — detects only the legacy prefix
 *
 * Note: Web Crypto functions (deriveKey, encryptNote, etc.) require a browser
 *       context and are not tested here.
 */

// Polyfill browser base64 globals for Jest / Node.js
global.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
global.btoa = (bin) => Buffer.from(bin, "binary").toString("base64");

const {
    bytesToBase64,
    base64ToBytes,
    isEncryptedPayload,
    wrapEncryptedPayload,
    unwrapEncryptedPayload,
    isEnvelopeEncryptedPayload,
    isLegacyEncryptedPayload,
    LEGACY_CONTENT_PREFIX,
    ENVELOPE_CONTENT_PREFIX,
} = require("../crypto");


// ── bytesToBase64 ─────────────────────────────────────────────────────────────

describe("bytesToBase64", () => {
    test("encodes a single zero byte", () => {
        expect(bytesToBase64(new Uint8Array([0]))).toBe("AA==");
    });

    test("encodes known bytes to expected base64", () => {
        // [72, 101, 108, 108, 111] = "Hello" in ASCII
        const bytes = new Uint8Array([72, 101, 108, 108, 111]);
        expect(bytesToBase64(bytes)).toBe(btoa("Hello"));
    });

    test("encodes empty array to empty string", () => {
        expect(bytesToBase64(new Uint8Array([]))).toBe("");
    });

    test("handles all 256 byte values without throwing", () => {
        const all = new Uint8Array(256);
        for (let i = 0; i < 256; i++) all[i] = i;
        expect(() => bytesToBase64(all)).not.toThrow();
    });

    test("output contains only valid base64 characters", () => {
        const bytes = new Uint8Array(64).fill(0xAB);
        const result = bytesToBase64(bytes);
        expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
});


// ── base64ToBytes ─────────────────────────────────────────────────────────────

describe("base64ToBytes", () => {
    test("decodes 'AA==' to a single zero byte", () => {
        const result = base64ToBytes("AA==");
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result).toEqual(new Uint8Array([0]));
    });

    test("decodes known base64 back to bytes", () => {
        const result = base64ToBytes(btoa("Hello"));
        expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
    });

    test("returns a Uint8Array", () => {
        expect(base64ToBytes("AAAA")).toBeInstanceOf(Uint8Array);
    });
});


// ── bytesToBase64 / base64ToBytes round-trip ──────────────────────────────────

describe("bytesToBase64 / base64ToBytes round-trip", () => {
    test("recovers original bytes for 1 byte", () => {
        const original = new Uint8Array([42]);
        expect(base64ToBytes(bytesToBase64(original))).toEqual(original);
    });

    test("recovers original bytes for 32 random-ish bytes", () => {
        const original = new Uint8Array(32).map((_, i) => (i * 37 + 13) % 256);
        expect(base64ToBytes(bytesToBase64(original))).toEqual(original);
    });

    test("recovers original bytes for all 256 values", () => {
        const original = new Uint8Array(256).map((_, i) => i);
        expect(base64ToBytes(bytesToBase64(original))).toEqual(original);
    });
});


// ── Payload prefix constants ──────────────────────────────────────────────────

describe("payload prefix constants", () => {
    test("LEGACY_CONTENT_PREFIX is 'enc:v1:'", () => {
        expect(LEGACY_CONTENT_PREFIX).toBe("enc:v1:");
    });

    test("ENVELOPE_CONTENT_PREFIX is 'enc:v2:'", () => {
        expect(ENVELOPE_CONTENT_PREFIX).toBe("enc:v2:");
    });

    test("the two prefixes are different", () => {
        expect(LEGACY_CONTENT_PREFIX).not.toBe(ENVELOPE_CONTENT_PREFIX);
    });
});


// ── isEncryptedPayload ────────────────────────────────────────────────────────

describe("isEncryptedPayload", () => {
    test("returns true for legacy prefix", () => {
        expect(isEncryptedPayload("enc:v1:abc123")).toBe(true);
    });

    test("returns true for envelope prefix", () => {
        expect(isEncryptedPayload("enc:v2:xyz456")).toBe(true);
    });

    test("returns false for plain text", () => {
        expect(isEncryptedPayload("Hello world")).toBe(false);
    });

    test("returns false for empty string", () => {
        expect(isEncryptedPayload("")).toBe(false);
    });

    test("returns false for null", () => {
        expect(isEncryptedPayload(null)).toBe(false);
    });

    test("returns false for a number", () => {
        expect(isEncryptedPayload(42)).toBe(false);
    });

    test("returns false for partial prefix match ('enc:v')", () => {
        expect(isEncryptedPayload("enc:v")).toBe(false);
    });
});


// ── wrapEncryptedPayload ──────────────────────────────────────────────────────

describe("wrapEncryptedPayload", () => {
    test("adds the envelope prefix", () => {
        expect(wrapEncryptedPayload("abc123")).toBe("enc:v2:abc123");
    });

    test("wrapped result is detected as encrypted payload", () => {
        expect(isEncryptedPayload(wrapEncryptedPayload("data"))).toBe(true);
    });

    test("wrapped result is detected as envelope encrypted", () => {
        expect(isEnvelopeEncryptedPayload(wrapEncryptedPayload("data"))).toBe(true);
    });

    test("wrapped result is NOT detected as legacy encrypted", () => {
        expect(isLegacyEncryptedPayload(wrapEncryptedPayload("data"))).toBe(false);
    });

    test("wrapping empty string gives prefix only", () => {
        expect(wrapEncryptedPayload("")).toBe("enc:v2:");
    });
});


// ── unwrapEncryptedPayload ────────────────────────────────────────────────────

describe("unwrapEncryptedPayload", () => {
    test("strips envelope prefix", () => {
        expect(unwrapEncryptedPayload("enc:v2:abc123")).toBe("abc123");
    });

    test("strips legacy prefix", () => {
        expect(unwrapEncryptedPayload("enc:v1:old_data")).toBe("old_data");
    });

    test("returns value unchanged when no prefix present", () => {
        expect(unwrapEncryptedPayload("plain text")).toBe("plain text");
    });

    test("returns non-string values unchanged", () => {
        expect(unwrapEncryptedPayload(null)).toBe(null);
        expect(unwrapEncryptedPayload(undefined)).toBe(undefined);
        expect(unwrapEncryptedPayload(42)).toBe(42);
    });

    test("round-trip: wrap then unwrap returns original", () => {
        const original = "base64ciphertexthere==";
        expect(unwrapEncryptedPayload(wrapEncryptedPayload(original))).toBe(original);
    });
});


// ── isEnvelopeEncryptedPayload ────────────────────────────────────────────────

describe("isEnvelopeEncryptedPayload", () => {
    test("returns true for enc:v2: prefix", () => {
        expect(isEnvelopeEncryptedPayload("enc:v2:data")).toBe(true);
    });

    test("returns false for enc:v1: prefix", () => {
        expect(isEnvelopeEncryptedPayload("enc:v1:data")).toBe(false);
    });

    test("returns false for plain text", () => {
        expect(isEnvelopeEncryptedPayload("plain")).toBe(false);
    });
});


// ── isLegacyEncryptedPayload ──────────────────────────────────────────────────

describe("isLegacyEncryptedPayload", () => {
    test("returns true for enc:v1: prefix", () => {
        expect(isLegacyEncryptedPayload("enc:v1:data")).toBe(true);
    });

    test("returns false for enc:v2: prefix", () => {
        expect(isLegacyEncryptedPayload("enc:v2:data")).toBe(false);
    });

    test("returns false for plain text", () => {
        expect(isLegacyEncryptedPayload("plain")).toBe(false);
    });
});

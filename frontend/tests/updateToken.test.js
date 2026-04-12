"use strict";
/**
 * Unit tests for the XOR-based Updatable Encryption (UE) token mathematics.
 *
 * This is the core security property of the thesis protocol:
 *   enc_dek = GK ⊕ DEK             (wrapping)
 *   DEK     = GK ⊕ enc_dek         (unwrapping)
 *   token   = oldGK ⊕ newGK        (rotation token sent to server)
 *   enc_dek_new = enc_dek_old ⊕ token
 *             = (oldGK ⊕ DEK) ⊕ (oldGK ⊕ newGK)
 *             = newGK ⊕ DEK        ✓
 *
 * The server applies the token without ever seeing oldGK, newGK, or the DEK —
 * this is the "ciphertext-independent" updatable encryption property.
 *
 * All functions here are pure Uint8Array operations that mirror the logic in
 * sodiumCrypto.js (xorBytes) and updatableNotesCrypto.js (wrapDEK/unwrapDEK).
 * We test the mathematics independently of the libsodium library.
 */

// ── Pure XOR helper (mirrors sodiumCrypto.xorBytes) ──────────────────────────

function xorBytes(a, b) {
    if (a.length !== b.length) throw new Error("xorBytes: length mismatch");
    return a.map((v, i) => v ^ b[i]);
}

// ── Mirrors updatableNotesCrypto.wrapDEK / unwrapDEK ─────────────────────────

const wrapDEK   = (gk, dek)       => xorBytes(gk, dek);
const unwrapDEK = (gk, wrappedDek) => xorBytes(gk, wrappedDek);

// ── Test helpers ──────────────────────────────────────────────────────────────

/** Produce a deterministic 32-byte key from a seed value. */
function makeKey(seed) {
    return new Uint8Array(32).map((_, i) => (seed + i * 7) % 256);
}

function randomLike(seed, len = 32) {
    return new Uint8Array(len).map((_, i) => (seed * 31 + i * 17 + 3) % 256);
}

// ── xorBytes ─────────────────────────────────────────────────────────────────

describe("xorBytes", () => {
    test("XOR of identical arrays is all zeros", () => {
        const a = makeKey(42);
        const result = xorBytes(a, a);
        expect(Array.from(result).every(b => b === 0)).toBe(true);
    });

    test("XOR is commutative: a⊕b === b⊕a", () => {
        const a = makeKey(10);
        const b = makeKey(20);
        expect(xorBytes(a, b)).toEqual(xorBytes(b, a));
    });

    test("XOR is its own inverse: (a⊕b)⊕b === a", () => {
        const a = makeKey(5);
        const b = makeKey(99);
        expect(xorBytes(xorBytes(a, b), b)).toEqual(a);
    });

    test("XOR with all-zero array is identity", () => {
        const a = makeKey(77);
        const zeros = new Uint8Array(32);
        expect(xorBytes(a, zeros)).toEqual(a);
    });

    test("throws when arrays have different lengths", () => {
        expect(() => xorBytes(new Uint8Array(32), new Uint8Array(16))).toThrow("length mismatch");
    });

    test("returns a Uint8Array", () => {
        expect(xorBytes(makeKey(1), makeKey(2))).toBeInstanceOf(Uint8Array);
    });

    test("result length equals input length", () => {
        const a = makeKey(1);
        expect(xorBytes(a, makeKey(2))).toHaveLength(a.length);
    });
});


// ── DEK wrap / unwrap ─────────────────────────────────────────────────────────

describe("wrapDEK / unwrapDEK", () => {
    test("unwrap(wrap(dek)) recovers original DEK", () => {
        const gk  = makeKey(11);
        const dek = makeKey(22);
        expect(unwrapDEK(gk, wrapDEK(gk, dek))).toEqual(dek);
    });

    test("wrap(gk, dek) !== dek when gk is non-zero", () => {
        const gk  = makeKey(11);
        const dek = makeKey(22);
        expect(wrapDEK(gk, dek)).not.toEqual(dek);
    });

    test("different DEKs produce different wrapped values under the same GK", () => {
        const gk   = makeKey(5);
        const dek1 = makeKey(10);
        const dek2 = makeKey(20);
        expect(wrapDEK(gk, dek1)).not.toEqual(wrapDEK(gk, dek2));
    });

    test("same DEK wrapped under different GKs produces different output", () => {
        const dek  = makeKey(99);
        const gk1  = makeKey(1);
        const gk2  = makeKey(2);
        expect(wrapDEK(gk1, dek)).not.toEqual(wrapDEK(gk2, dek));
    });

    test("wrap is symmetric: wrapDEK(gk, dek) === wrapDEK(dek, gk)", () => {
        const gk  = makeKey(7);
        const dek = makeKey(13);
        expect(wrapDEK(gk, dek)).toEqual(wrapDEK(dek, gk));
    });
});


// ── Ciphertext-independent update token ──────────────────────────────────────
//
// This is the central UE security property tested in the thesis.
// The server applies the token to every stored enc_dek without seeing the DEK.

describe("ciphertext-independent update token", () => {

    test("applying token re-wraps enc_dek under the new GK", () => {
        const dek    = randomLike(1);
        const oldGK  = randomLike(2);
        const newGK  = randomLike(3);

        const encDekOld  = wrapDEK(oldGK, dek);           // what the server stores
        const token      = xorBytes(oldGK, newGK);         // what client sends to server
        const encDekNew  = xorBytes(encDekOld, token);     // server applies blindly

        // The server must now be able to recover the DEK using the new GK
        const recoveredDek = unwrapDEK(newGK, encDekNew);
        expect(recoveredDek).toEqual(dek);
    });

    test("old GK can no longer unwrap the updated enc_dek", () => {
        const dek    = randomLike(10);
        const oldGK  = randomLike(20);
        const newGK  = randomLike(30);

        const encDekOld = wrapDEK(oldGK, dek);
        const token     = xorBytes(oldGK, newGK);
        const encDekNew = xorBytes(encDekOld, token);

        // Old GK produces wrong DEK
        const wrongDek = unwrapDEK(oldGK, encDekNew);
        expect(wrongDek).not.toEqual(dek);
    });

    test("token reveals no information about the DEK (token is independent of DEK)", () => {
        const oldGK  = randomLike(5);
        const newGK  = randomLike(6);
        const token  = xorBytes(oldGK, newGK);

        // Token is purely a function of oldGK and newGK, not the DEK
        const dek1 = randomLike(100);
        const dek2 = randomLike(200);
        const encDek1New = xorBytes(wrapDEK(oldGK, dek1), token);
        const encDek2New = xorBytes(wrapDEK(oldGK, dek2), token);

        expect(unwrapDEK(newGK, encDek1New)).toEqual(dek1);
        expect(unwrapDEK(newGK, encDek2New)).toEqual(dek2);
    });

    test("multiple rotations work correctly", () => {
        const dek   = randomLike(1);
        let   curGK = randomLike(2);
        let   encDek = wrapDEK(curGK, dek);

        // Simulate 5 group-key rotations
        for (let i = 3; i < 8; i++) {
            const nextGK = randomLike(i * 10);
            const token  = xorBytes(curGK, nextGK);
            encDek = xorBytes(encDek, token);   // server applies token
            curGK  = nextGK;
        }

        // After all rotations the DEK is still recoverable with the final GK
        expect(unwrapDEK(curGK, encDek)).toEqual(dek);
    });

    test("token application order does not matter (two rotations commute)", () => {
        // If the server applies two independent tokens the order should not matter
        // because XOR is commutative and associative.
        const dek    = randomLike(1);
        const gk0    = randomLike(2);
        const gk1    = randomLike(3);
        const gk2    = randomLike(4);

        const encDek0 = wrapDEK(gk0, dek);
        const token01 = xorBytes(gk0, gk1);
        const token12 = xorBytes(gk1, gk2);

        // Apply in order: 0→1 then 1→2
        const forward = xorBytes(xorBytes(encDek0, token01), token12);

        // Apply combined token (XOR of both) at once
        const combined = xorBytes(token01, token12);
        const oneShot  = xorBytes(encDek0, combined);

        expect(forward).toEqual(oneShot);
        expect(unwrapDEK(gk2, forward)).toEqual(dek);
    });

    test("tampered token yields wrong DEK (integrity check by AEAD)", () => {
        const dek    = randomLike(7);
        const oldGK  = randomLike(8);
        const newGK  = randomLike(9);

        const encDekOld   = wrapDEK(oldGK, dek);
        const token       = xorBytes(oldGK, newGK);
        // Flip one bit in the token (simulates a tampered server-side operation)
        const badToken    = token.slice();
        badToken[0] ^= 0xFF;
        const badEncDekNew = xorBytes(encDekOld, badToken);

        expect(unwrapDEK(newGK, badEncDekNew)).not.toEqual(dek);
    });
});

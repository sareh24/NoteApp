"use strict";
/**
 * fingerprint.js — Pure fingerprinting and watermarking helpers
 *
 * Extracted from noteView.html so they can be unit-tested independently.
 * All functions are stateless and have no DOM dependency.
 *
 * Encoding scheme:
 *   - FP_MARKER (\u200B\u200B) — start / end delimiter
 *   - \u200C — bit 0
 *   - \u200D — bit 1
 *   Bits are packed MSB-first per byte, then base64-encoded for storage/transport.
 */

// Two consecutive zero-width spaces mark the start and end of a fingerprint sequence.
const FP_MARKER = '\u200B\u200B';

/**
 * Embed a base64-encoded fingerprint as invisible Unicode zero-width characters
 * inside an HTML string.  The hidden sequence is inserted after EVERY block-level
 * opening tag so that any partial copy of the rendered text still carries the
 * fingerprint.
 *
 * @param {string} html           - Raw HTML string (e.g. "<p>Hello</p>")
 * @param {string} fingerprintB64 - Base64-encoded fingerprint bytes
 * @returns {string}              - HTML with fingerprint injected after every block opener
 */
function embedFingerprint(html, fingerprintB64) {
    const bytes = Uint8Array.from(atob(fingerprintB64), c => c.charCodeAt(0));
    let hidden = FP_MARKER; // start marker
    for (const byte of bytes) {
        for (let bit = 7; bit >= 0; bit--) {
            hidden += (byte >> bit) & 1 ? '\u200D' : '\u200C';
        }
    }
    hidden += FP_MARKER; // end marker
    return html.replace(/(<(?:p|div|h[1-6]|li|blockquote|section|article)[^>]*>)/gi, '$1' + hidden);
}

/**
 * Extract a base64-encoded fingerprint from a plain-text string that was
 * previously rendered from fingerprinted HTML.
 *
 * @param {string} text - Pasted/copied plain text (may contain zero-width chars)
 * @returns {string|null} - Base64 fingerprint string, or null if none found
 */
function extractFingerprint(text) {
    const start = text.indexOf(FP_MARKER);
    if (start === -1) return null;
    const end = text.indexOf(FP_MARKER, start + FP_MARKER.length);
    if (end === -1) return null;
    const bits = Array.from(text.slice(start + FP_MARKER.length, end))
        .map(c => c === '\u200D' ? '1' : c === '\u200C' ? '0' : null)
        .filter(b => b !== null)
        .join('');
    if (bits.length < 8) return null;
    const byteArr = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        byteArr.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return btoa(String.fromCharCode(...byteArr));
}

/**
 * Insert a small visible watermark (recipient's name) at the end of every
 * paragraph in an HTML string.
 *
 * @param {string} html          - Raw HTML string
 * @param {string} recipientName - Full name to embed (e.g. "Alice Smith")
 * @returns {string}             - HTML with watermark spans injected before every </p>
 */
function addWatermark(html, recipientName) {
    const mark = `<span style="color:#ccc;font-size:9px;font-style:italic;user-select:text;"> — ${recipientName}</span>`;
    return html.replace(/<\/p>/gi, mark + '</p>');
}

module.exports = { FP_MARKER, embedFingerprint, extractFingerprint, addWatermark };

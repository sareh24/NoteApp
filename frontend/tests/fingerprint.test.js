"use strict";
/**
 * Unit tests for fingerprint.js
 *
 * Covers:
 *   - embedFingerprint()   — encodes bytes as zero-width chars inside HTML
 *   - extractFingerprint() — decodes the hidden bits back to base64
 *   - addWatermark()       — injects visible recipient name into paragraphs
 *   - round-trip property  — embed then extract always recovers the original
 */

// atob / btoa are browser globals; provide Node.js equivalents for Jest.
global.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
global.btoa = (bin) => Buffer.from(bin, "binary").toString("base64");

const { FP_MARKER, embedFingerprint, extractFingerprint, addWatermark } =
    require("../fingerprint");

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a deterministic base64 string from n bytes (0x00…0xFF cycling). */
function makeB64(nBytes) {
    const arr = new Uint8Array(nBytes);
    for (let i = 0; i < nBytes; i++) arr[i] = i % 256;
    return btoa(String.fromCharCode(...arr));
}

/** Strip every HTML tag and return the remaining visible + invisible text. */
function innerText(html) {
    return html.replace(/<[^>]*>/g, "");
}

// ── FP_MARKER constant ────────────────────────────────────────────────────────

describe("FP_MARKER", () => {
    test("is exactly two consecutive zero-width spaces (U+200B)", () => {
        expect(FP_MARKER).toBe("\u200B\u200B");
        expect(FP_MARKER).toHaveLength(2);
    });
});

// ── embedFingerprint ──────────────────────────────────────────────────────────

describe("embedFingerprint", () => {
    test("returns a string", () => {
        const result = embedFingerprint("<p>Hello</p>", makeB64(4));
        expect(typeof result).toBe("string");
    });

    test("output contains both FP_MARKER occurrences", () => {
        const result = embedFingerprint("<p>Hello</p>", makeB64(4));
        const first = result.indexOf(FP_MARKER);
        expect(first).toBeGreaterThanOrEqual(0);
        const second = result.indexOf(FP_MARKER, first + FP_MARKER.length);
        expect(second).toBeGreaterThan(first);
    });

    test("injects hidden chars after a <p> tag", () => {
        const result = embedFingerprint("<p>Hi</p>", makeB64(1));
        expect(result.startsWith("<p>")).toBe(true);
        // Character immediately after <p> should be part of the fingerprint
        expect(result[3]).toBe("\u200B");
    });

    test("injects hidden chars after every block-level opening tag", () => {
        const html = "<p>Para</p><div>Div</div><h1>H1</h1><li>Item</li>";
        const result = embedFingerprint(html, makeB64(2));
        // Count how many FP_MARKER start sequences appear (one per tag pair)
        const tagCount = (result.match(/<(?:p|div|h[1-6]|li|blockquote|section|article)[^>]*>/gi) || []).length;
        let markerCount = 0;
        let pos = 0;
        while ((pos = result.indexOf(FP_MARKER, pos)) !== -1) { markerCount++; pos++; }
        // Each tag gets a start + end marker pair, so markerCount = tagCount * 2
        expect(markerCount).toBe(tagCount * 2);
    });

    test("does NOT inject into non-block tags (span, a, strong)", () => {
        const html = "<p>Text <span>span</span> <a href='#'>link</a></p>";
        const result = embedFingerprint(html, makeB64(2));
        // Fingerprint only after <p>, not after <span> or <a>
        const afterSpan = result.indexOf("<span>") + "<span>".length;
        expect(result[afterSpan]).not.toBe("\u200B");
        const afterA = result.indexOf("<a href='#'>") + "<a href='#'>".length;
        expect(result[afterA]).not.toBe("\u200B");
    });

    test("hidden sequence between markers contains only U+200B, U+200C, U+200D", () => {
        const result = embedFingerprint("<p>Test</p>", makeB64(4));
        const text = innerText(result);
        const start = text.indexOf(FP_MARKER) + FP_MARKER.length;
        const end = text.indexOf(FP_MARKER, start);
        const between = Array.from(text.slice(start, end));
        const invalid = between.filter(
            c => c !== "\u200B" && c !== "\u200C" && c !== "\u200D"
        );
        expect(invalid).toEqual([]);
    });

    test("different fingerprints produce different hidden sequences", () => {
        const fp1 = embedFingerprint("<p>X</p>", makeB64(4));
        const fp2 = embedFingerprint("<p>X</p>", makeB64(8));
        expect(fp1).not.toBe(fp2);
    });

    test("leaves visible HTML text unchanged", () => {
        const html = "<p>Hello world</p>";
        const result = embedFingerprint(html, makeB64(4));
        expect(result).toContain("Hello world");
    });

    test("works with a single byte (8 bits + 2 markers)", () => {
        const oneByte = btoa(String.fromCharCode(0b10101010)); // "qg=="
        const result = embedFingerprint("<p>x</p>", oneByte);
        // Extract the bit sequence between the two markers
        const text = innerText(result);
        const start = text.indexOf(FP_MARKER) + FP_MARKER.length;
        const end = text.indexOf(FP_MARKER, start);
        const bits = Array.from(text.slice(start, end))
            .map(c => c === "\u200D" ? "1" : "0")
            .join("");
        expect(bits).toBe("10101010");
    });

    test("handles HTML with attributes on block tags", () => {
        const html = '<p class="intro">Text</p>';
        const result = embedFingerprint(html, makeB64(2));
        expect(result).toContain('<p class="intro">');
        // Marker injected right after the tag
        const tagEnd = result.indexOf('>') + 1;
        expect(result[tagEnd]).toBe("\u200B");
    });
});

// ── extractFingerprint ────────────────────────────────────────────────────────

describe("extractFingerprint", () => {
    test("returns null when no marker present", () => {
        expect(extractFingerprint("plain text with no hidden chars")).toBeNull();
    });

    test("returns null when only the start marker is present", () => {
        expect(extractFingerprint(`before${FP_MARKER}after`)).toBeNull();
    });

    test("returns null when bit sequence is too short (< 8 bits)", () => {
        // Only 4 bit-chars between markers
        const text = `${FP_MARKER}\u200C\u200D\u200C\u200D${FP_MARKER}`;
        expect(extractFingerprint(text)).toBeNull();
    });

    test("returns a string when fingerprint is found", () => {
        const b64 = makeB64(4);
        const embedded = embedFingerprint("<p>Hi</p>", b64);
        const plain = innerText(embedded);
        expect(typeof extractFingerprint(plain)).toBe("string");
    });

    test("ignores visible text between the markers (only counts 200C/200D)", () => {
        // Insert some visible ASCII between the hidden chars — should be filtered out
        const text = `${FP_MARKER}A\u200CB\u200DC${FP_MARKER}`;
        // Only 1 bit 0 + 1 bit 1 = 2 bits < 8 → null (not enough bits)
        expect(extractFingerprint(text)).toBeNull();
    });

    test("uses the FIRST occurrence of FP_MARKER as start", () => {
        // Even when there are multiple FP_MARKER occurrences, only first pair is used
        const b64 = makeB64(2);
        const plain = innerText(embedFingerprint("<p>A</p><p>B</p>", b64));
        // Multiple markers exist; extract should still work
        expect(extractFingerprint(plain)).not.toBeNull();
    });
});

// ── Round-trip (embed → extract) ─────────────────────────────────────────────

describe("round-trip: embed then extract", () => {
    test("recovers original b64 for 1 byte", () => {
        const b64 = btoa(String.fromCharCode(0xFF));
        const plain = innerText(embedFingerprint("<p>x</p>", b64));
        expect(extractFingerprint(plain)).toBe(b64);
    });

    test("recovers original b64 for 4 bytes", () => {
        const b64 = makeB64(4);
        const plain = innerText(embedFingerprint("<p>x</p>", b64));
        expect(extractFingerprint(plain)).toBe(b64);
    });

    test("recovers original b64 for 16 bytes (typical fingerprint size)", () => {
        const b64 = makeB64(16);
        const plain = innerText(embedFingerprint("<p>x</p>", b64));
        expect(extractFingerprint(plain)).toBe(b64);
    });

    test("recovers original b64 for 32 bytes (max fingerprint size)", () => {
        const b64 = makeB64(32);
        const plain = innerText(embedFingerprint("<p>x</p>", b64));
        expect(extractFingerprint(plain)).toBe(b64);
    });

    test("recovers fingerprint from multi-paragraph HTML (partial copy scenario)", () => {
        const b64 = makeB64(8);
        const html = "<p>Intro</p><p>Middle paragraph text here.</p><p>Conclusion.</p>";
        const embedded = embedFingerprint(html, b64);
        // Simulate copying only the second paragraph's text
        const secondParaMatch = embedded.match(/<p[^>]*>([\s\S]*?)<\/p>/g);
        expect(secondParaMatch).not.toBeNull();
        const secondParaText = innerText(secondParaMatch[1]);
        expect(extractFingerprint(secondParaText)).toBe(b64);
    });

    test("same b64 round-trips consistently (deterministic encoding)", () => {
        const b64 = makeB64(8);
        const html = "<p>Test</p>";
        const r1 = innerText(embedFingerprint(html, b64));
        const r2 = innerText(embedFingerprint(html, b64));
        expect(extractFingerprint(r1)).toBe(extractFingerprint(r2));
    });

    test("two different fingerprints produce different extracted results", () => {
        const b64a = makeB64(4);
        const b64b = makeB64(8);
        const plain_a = innerText(embedFingerprint("<p>x</p>", b64a));
        const plain_b = innerText(embedFingerprint("<p>x</p>", b64b));
        expect(extractFingerprint(plain_a)).not.toBe(extractFingerprint(plain_b));
    });
});

// ── addWatermark ──────────────────────────────────────────────────────────────

describe("addWatermark", () => {
    test("returns a string", () => {
        expect(typeof addWatermark("<p>Hi</p>", "Alice")).toBe("string");
    });

    test("injects recipient name before </p>", () => {
        const result = addWatermark("<p>Hello</p>", "Alice Smith");
        expect(result).toContain("Alice Smith");
        expect(result).toContain("</p>");
        // Name appears before the closing tag
        const namePos = result.indexOf("Alice Smith");
        const closePos = result.indexOf("</p>");
        expect(namePos).toBeLessThan(closePos);
    });

    test("watermarks every paragraph", () => {
        const html = "<p>First</p><p>Second</p><p>Third</p>";
        const result = addWatermark(html, "Bob Jones");
        const occurrences = (result.match(/Bob Jones/g) || []).length;
        expect(occurrences).toBe(3);
    });

    test("preserves original text content", () => {
        const result = addWatermark("<p>Original text</p>", "Alice");
        expect(result).toContain("Original text");
    });

    test("does not alter non-paragraph tags", () => {
        const html = "<div>Div content</div><p>Para</p>";
        const result = addWatermark(html, "Alice");
        expect(result).toContain("<div>Div content</div>");
    });

    test("is case-insensitive for </P> variants", () => {
        const result = addWatermark("<p>Text</P>", "Alice");
        expect(result).toContain("Alice");
    });

    test("returns unchanged HTML when there are no paragraphs", () => {
        const html = "<div>No paragraphs here</div>";
        const result = addWatermark(html, "Alice");
        expect(result).toBe(html);
    });

    test("watermark span has expected inline style attributes", () => {
        const result = addWatermark("<p>x</p>", "Alice");
        expect(result).toContain("font-size:9px");
        expect(result).toContain("color:#ccc");
        expect(result).toContain("font-style:italic");
    });

    test("different recipient names produce different output", () => {
        const html = "<p>Text</p>";
        expect(addWatermark(html, "Alice")).not.toBe(addWatermark(html, "Bob"));
    });

    test("handles special HTML characters in recipient name safely", () => {
        // Should embed name literally (not escape — consistent with current impl)
        const result = addWatermark("<p>x</p>", "O'Brien");
        expect(result).toContain("O'Brien");
    });
});

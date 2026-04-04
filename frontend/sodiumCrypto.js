import sodium from "https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.13/+esm";

const te = new TextEncoder();
const td = new TextDecoder();

export async function sodiumReady() {
  await sodium.ready;
}

export function b64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}
export function unb64(s) {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}
export function utf8(s) {
  return te.encode(s);
}
export function utf8dec(b) {
  return td.decode(b);
}

export function randomBytes(n) {
  return sodium.randombytes_buf(n);
}

// XOR two equal-length Uint8Arrays — used for ciphertext-independent UE token application
export function xorBytes(a, b) {
  if (a.length !== b.length) throw new Error("xorBytes: length mismatch");
  return a.map((v, i) => v ^ b[i]);
}

// X25519 keypair for sharing
export function generateUserKeypair() {
  const kp = sodium.crypto_box_keypair();
  return {
    publicKeyB64: b64(kp.publicKey),
    privateKeyB64: b64(kp.privateKey),
  };
}

// Encrypt GK to recipient (sealed box)
export function sealToRecipient(recipientPublicKeyB64, plaintextBytes) {
  const pk = unb64(recipientPublicKeyB64);
  const sealed = sodium.crypto_box_seal(plaintextBytes, pk);
  return b64(sealed);
}

// Recipient decrypts GK
export function openSealedForMe(myPublicKeyB64, myPrivateKeyB64, sealedB64) {
  const pk = unb64(myPublicKeyB64);
  const sk = unb64(myPrivateKeyB64);
  const sealed = unb64(sealedB64);
  return sodium.crypto_box_seal_open(sealed, pk, sk); // Uint8Array
}

// AEAD (XChaCha20-Poly1305) for content + wrapping DEKs under GK
export function aeadEncrypt(key32, plaintextBytes, aadBytes = new Uint8Array()) {
  const nonce = randomBytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    aadBytes,
    null,
    nonce,
    key32
  );
  return { nonceB64: b64(nonce), ciphertextB64: b64(ct) };
}

export function aeadDecrypt(key32, nonceB64, ciphertextB64, aadBytes = new Uint8Array()) {
  const nonce = unb64(nonceB64);
  const ct = unb64(ciphertextB64);
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ct,
    aadBytes,
    nonce,
    key32
  );
}
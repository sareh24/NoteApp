import {
  sodiumReady,
  randomBytes,
  aeadEncrypt,
  aeadDecrypt,
  utf8,
  utf8dec,
  b64,
  unb64,
  xorBytes,
  sealToRecipient,
  openSealedForMe,
} from "./sodiumCrypto.js";

function aadForContent(noteId, version) {
  return utf8(`note:${noteId};ver:${version};type:content`);
}

async function decryptCurrentGroupKey({ myPublicKeyB64, myPrivateKeyB64, myEncGkB64 }) {
  await sodiumReady();
  return openSealedForMe(myPublicKeyB64, myPrivateKeyB64, myEncGkB64);
}

// DEK wrapping uses XOR so the server can apply a ciphertext-independent update token.
//   enc_dek = GK ⊕ DEK  (32 bytes, no nonce needed)
// Integrity of the DEK is guaranteed indirectly: a tampered enc_dek produces a wrong DEK,
// which causes the AEAD content decryption to fail (tag mismatch).
function wrapDEK(groupKey, dek) {
  return xorBytes(groupKey, dek);
}

function unwrapDEK(groupKey, wrappedDekBytes) {
  return xorBytes(groupKey, wrappedDekBytes);
}

function buildEncryptedVersion({ noteId, version, gkVersion, plaintext, groupKey }) {
  const dek = randomBytes(32);
  const contentEnc = aeadEncrypt(dek, utf8(plaintext), aadForContent(noteId, version));
  const wrappedDek = wrapDEK(groupKey, dek);

  return {
    version,
    gk_version: gkVersion,
    content_nonce_b64: contentEnc.nonceB64,
    content_ciphertext_b64: contentEnc.ciphertextB64,
    wrapped_dek_b64: b64(wrappedDek),
  };
}

export async function createInitialPrivateNotePayload({
  noteId,
  plaintext,
  ownerUserId,
  ownerPublicKeyB64,
  initialRecipientPublicKeysByUserId = {},
}) {
  await sodiumReady();

  const groupKey = randomBytes(32);
  const initialVersion = buildEncryptedVersion({
    noteId,
    version: 1,
    gkVersion: 1,
    plaintext,
    groupKey,
  });

  const recipients = {
    [ownerUserId]: ownerPublicKeyB64,
    ...initialRecipientPublicKeysByUserId,
  };

  const keyPackets = Object.entries(recipients).map(([userId, publicKeyB64]) => ({
    recipient_user_id: userId,
    gk_version: 1,
    enc_gk_b64: sealToRecipient(publicKeyB64, groupKey),
  }));

  return { initialVersion, keyPackets };
}

export async function createNextVersionPayload({
  noteId,
  version,
  gkVersion,
  plaintext,
  myPublicKeyB64,
  myPrivateKeyB64,
  myEncGkB64,
}) {
  const groupKey = await decryptCurrentGroupKey({
    myPublicKeyB64,
    myPrivateKeyB64,
    myEncGkB64,
  });

  return buildEncryptedVersion({
    noteId,
    version,
    gkVersion,
    plaintext,
    groupKey,
  });
}

export async function decryptProtocolNote({
  noteId,
  latestVersion,
  myPublicKeyB64,
  myPrivateKeyB64,
  myEncGkB64,
}) {
  if (!latestVersion) {
    throw new Error("Missing note version payload");
  }

  const groupKey = await decryptCurrentGroupKey({
    myPublicKeyB64,
    myPrivateKeyB64,
    myEncGkB64,
  });

  const dek = unwrapDEK(groupKey, unb64(latestVersion.wrapped_dek_b64));

  const plaintext = aeadDecrypt(
    dek,
    latestVersion.content_nonce_b64,
    latestVersion.content_ciphertext_b64,
    aadForContent(noteId, latestVersion.version)
  );

  return utf8dec(plaintext);
}

export async function createSharePacket({
  recipientUserId,
  recipientPublicKeyB64,
  gkVersion,
  myPublicKeyB64,
  myPrivateKeyB64,
  myEncGkB64,
}) {
  const groupKey = await decryptCurrentGroupKey({
    myPublicKeyB64,
    myPrivateKeyB64,
    myEncGkB64,
  });

  return {
    recipient_id: recipientUserId,
    gk_version: gkVersion,
    enc_gk_b64: sealToRecipient(recipientPublicKeyB64, groupKey),
  };
}

// Generates a new GK, an update token, and new key packets for all remaining recipients.
//
// The update token Δ = oldGK ⊕ newGK allows the server to re-wrap every version's
// enc_dek without ever seeing the DEK or content:
//   enc_dek_new = enc_dek_old ⊕ Δ = (oldGK ⊕ DEK) ⊕ (oldGK ⊕ newGK) = newGK ⊕ DEK
//
// This is the ciphertext-independent updatable encryption property.
export async function createGroupKeyRotation({
  newGkVersion,
  recipientPublicKeysByUserId,
  myPublicKeyB64,
  myPrivateKeyB64,
  myEncGkB64,
}) {
  await sodiumReady();

  const oldGroupKey = await decryptCurrentGroupKey({
    myPublicKeyB64,
    myPrivateKeyB64,
    myEncGkB64,
  });

  const newGroupKey = randomBytes(32);

  // Token sent to server; server applies it blindly to all enc_dek values
  const updateToken = b64(xorBytes(oldGroupKey, newGroupKey));

  const keyPackets = Object.entries(recipientPublicKeysByUserId).map(([userId, publicKeyB64]) => ({
    recipient_user_id: userId,
    gk_version: newGkVersion,
    enc_gk_b64: sealToRecipient(publicKeyB64, newGroupKey),
  }));

  return {
    new_gk_version: newGkVersion,
    update_token_b64: updateToken,
    key_packets: keyPackets,
  };
}

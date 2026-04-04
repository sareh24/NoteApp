import { sodiumReady, generateUserKeypair } from "./sodiumCrypto.js";

const LEGACY_PUB_KEY_ITEM = "noteapp_user_pubkey_b64";
const LEGACY_PRIV_KEY_ITEM = "noteapp_user_privkey_b64";

function storageKey(userKey, suffix) {
  return `noteapp:${userKey}:${suffix}`;
}

export async function getOrCreateUserKeys(userKey) {
  await sodiumReady();

  if (!userKey) {
    throw new Error("A user identity is required to load protocol keys");
  }

  const publicKeyItem = storageKey(userKey, "pubkey_b64");
  const privateKeyItem = storageKey(userKey, "privkey_b64");

  let publicKeyB64 = localStorage.getItem(publicKeyItem);
  let privateKeyB64 = localStorage.getItem(privateKeyItem);

  if (!publicKeyB64 || !privateKeyB64) {
    const legacyPublicKeyB64 = localStorage.getItem(LEGACY_PUB_KEY_ITEM);
    const legacyPrivateKeyB64 = localStorage.getItem(LEGACY_PRIV_KEY_ITEM);
    if (legacyPublicKeyB64 && legacyPrivateKeyB64) {
        publicKeyB64 = legacyPublicKeyB64;
        privateKeyB64 = legacyPrivateKeyB64;
        localStorage.setItem(publicKeyItem, publicKeyB64);
        localStorage.setItem(privateKeyItem, privateKeyB64);
    }
  }

  if (!publicKeyB64 || !privateKeyB64) {
    const kp = generateUserKeypair();
    publicKeyB64 = kp.publicKeyB64;
    privateKeyB64 = kp.privateKeyB64;
    localStorage.setItem(publicKeyItem, publicKeyB64);
    localStorage.setItem(privateKeyItem, privateKeyB64);
  }

  return { publicKeyB64, privateKeyB64 };
}


export async function ensureProtocolPublicKeyPublished({ token, userKey, apiBase = "http://localhost:8000" }) {
  if (!token) {
    throw new Error("Missing auth token while publishing public key");
  }

  const keys = await getOrCreateUserKeys(userKey);
  const response = await fetch(`${apiBase}/auth/me/public-key`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({ public_key: keys.publicKeyB64 }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || "Could not publish your public key");
  }

  return keys;
}
import {
  randomBytes,
  hkdfSync,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
} from "node:crypto";

export type KeyPair = { publicKeyPem: string; privateKeyPem: string };

export function genEd25519(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}

export function genX25519(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}

export function hkdf256(
  secret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length = 32
): Uint8Array {
  const outUnknown: unknown = hkdfSync(
    "sha256",
    Buffer.from(salt),
    Buffer.from(secret),
    Buffer.from(info),
    length
  );
  // Node's hkdfSync returns Buffer (a Uint8Array). Some setups/types may say ArrayBuffer.
  // This ensures we always hand back a Uint8Array.
  return outUnknown instanceof Uint8Array
    ? outUnknown
    : new Uint8Array(outUnknown as ArrayBuffer);
}

export function ed25519Sign(
  payload: Uint8Array,
  privateKeyPem: string
): Buffer {
  // For Ed25519, algorithm must be `null` because hashing is built into the scheme
  return edSign(null, Buffer.from(payload), createPrivateKey(privateKeyPem));
}

export function ed25519Verify(
  payload: Uint8Array,
  publicKeyPem: string,
  signature: Uint8Array
): boolean {
  return edVerify(
    null,
    Buffer.from(payload),
    createPublicKey(publicKeyPem),
    Buffer.from(signature)
  );
}

export function dhX25519(
  privateKeyPem: string,
  otherPublicKeyPem: string
): Buffer {
  return diffieHellman({
    privateKey: createPrivateKey(privateKeyPem),
    publicKey: createPublicKey(otherPublicKeyPem),
  });
}

export function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
export function unb64(b64s: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64s, "base64"));
}
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
export function random(n: number): Buffer {
  return randomBytes(n);
}

// envelope.ts
import { AESCipher as Cipher } from "../wrappers.ts";
import { asBytes } from "../algorithms/utils/util.ts";
import {
  hkdf256,
  ed25519Sign,
  ed25519Verify,
  dhX25519,
  b64,
  utf8,
  random,
  genX25519,
} from "./cryptosuite.ts";

const INFO = utf8("demo:X25519+HKDF-SHA256->AES-256-CBC:1");

export type Envelope = {
  v: 1;
  alg: {
    kx: "X25519";
    kdf: "HKDF-SHA256";
    sym: "AES-256-CBC-PKCS7";
    sig: "Ed25519";
  };
  senderSigPubPem: string;
  ephKxPubPem: string;
  iv_b64: string;
  salt_b64: string;
  ct_b64: string;
  sig_b64: string;
};

function concat(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function serializeForSig(
  domain: Uint8Array,
  ephPubPem: string,
  recipPubPem: string,
  iv: Uint8Array,
  salt: Uint8Array,
  ct: Uint8Array
): Uint8Array {
  return concat([
    domain,
    utf8("|eph:"),
    utf8(ephPubPem),
    utf8("|rcp:"),
    utf8(recipPubPem),
    utf8("|iv:"),
    iv,
    utf8("|salt:"),
    salt,
    utf8("|ct:"),
    ct,
  ]);
}

export function createEnvelope(opts: {
  plaintextUtf8: string;
  senderSigPrivPem: string;
  senderSigPubPem: string;
  recipientKxPubPem: string;
}): Envelope {
  // 1) Ephemeral X25519
  const eph = genX25519();
  const ephPubPem = eph.publicKeyPem;
  const ephPrivPem = eph.privateKeyPem;

  // 2) ECDH -> HKDF (bytes everywhere)
  const shared = asBytes(dhX25519(ephPrivPem, opts.recipientKxPubPem)); // 32B
  const salt = random(16); // 16B
  const key = new Uint8Array(hkdf256(shared, salt, INFO, 32)); // 32B

  // 3) AES-256-CBC + PKCS7
  const iv = random(16);
  const aes = new Cipher(key, { mode: "CBC", iv, padding: "PKCS7" });
  const ct = aes.encrypt(utf8(opts.plaintextUtf8));

  // 4) Sign domain-bound envelope
  const sigPayload = serializeForSig(
    INFO,
    ephPubPem,
    opts.recipientKxPubPem,
    iv,
    salt,
    ct
  );
  const sig = ed25519Sign(sigPayload, opts.senderSigPrivPem);

  // 5) Debug (client)
  try {
    console.log("DBG ephPubPem =", b64(utf8(ephPubPem)));
    console.log("DBG recipPub  =", b64(utf8(opts.recipientKxPubPem)));
    console.log("DBG iv        =", b64(iv));
    console.log("DBG salt      =", b64(salt));
    console.log("DBG shared    =", b64(shared));
    console.log("DBG hkdfKey   =", b64(key));
    console.log("DBG ct.len    =", ct.length);
    console.log("DBG ct_b64    =", b64(ct)); // ⬅️ add this
  } catch {}

  return {
    v: 1,
    alg: {
      kx: "X25519",
      kdf: "HKDF-SHA256",
      sym: "AES-256-CBC-PKCS7",
      sig: "Ed25519",
    },
    senderSigPubPem: opts.senderSigPubPem,
    ephKxPubPem: ephPubPem,
    iv_b64: b64(iv),
    salt_b64: b64(salt),
    ct_b64: b64(ct),
    sig_b64: b64(sig),
  };
}

export function openEnvelope(
  env: Envelope,
  recipientKxPrivPem: string,
  recipientKxPubPem: string
): string {
  // 0) Decode fields -> Uint8Array
  const iv = new Uint8Array(Buffer.from(env.iv_b64, "base64"));
  const salt = new Uint8Array(Buffer.from(env.salt_b64, "base64"));
  const ct = new Uint8Array(Buffer.from(env.ct_b64, "base64"));
  const sig = new Uint8Array(Buffer.from(env.sig_b64, "base64"));

  // 1) ECDH -> HKDF
  const shared = asBytes(dhX25519(recipientKxPrivPem, env.ephKxPubPem)); // 32B
  const key = new Uint8Array(hkdf256(shared, salt, INFO, 32)); // 32B

  // 2) Pre-decrypt debug (so we always see values)
  try {
    console.log("SRV ephPubPem =", b64(utf8(env.ephKxPubPem)));
    console.log("SRV recipPub  =", b64(utf8(recipientKxPubPem)));
    console.log("SRV iv        =", b64(iv));
    console.log("SRV salt      =", b64(salt));
    console.log("SRV shared    =", b64(shared));
    console.log("SRV hkdfKey   =", b64(key));
    console.log("SRV ct.len    =", ct.length);
    console.log("SRV ct_b64    =", env.ct_b64); // ⬅️ add this
  } catch {}

  // 3) Verify signature (encrypt-then-sign)
  const payload = serializeForSig(
    INFO,
    env.ephKxPubPem,
    recipientKxPubPem,
    iv,
    salt,
    ct
  );
  if (!ed25519Verify(payload, env.senderSigPubPem, sig)) {
    throw new Error("Signature verification failed");
  }

  // 4) TEMPORARY: decrypt with padding disabled to inspect plaintext bytes
  //    (If this succeeds, the padding byte we'll print tells us exactly why unpad fails)
  const aesRaw = new Cipher(key, { mode: "CBC", iv, padding: "None" });
  const ptPadded = aesRaw.decrypt(ct);
  try {
    console.log("SRV ptPadded_b64 =", b64(ptPadded));
    console.log("SRV lastByte     =", ptPadded[ptPadded.length - 1] ?? -1);
    // Also show last block for clarity
    const lb = ptPadded.slice(Math.max(0, ptPadded.length - 16));
    console.log("SRV lastBlock_b64=", b64(lb));
  } catch {}

  // 5) REAL decrypt (with PKCS7)
  const aes = new Cipher(key, { mode: "CBC", iv, padding: "PKCS7" });
  const pt = aes.decrypt(ct);

  return new TextDecoder().decode(pt);
}

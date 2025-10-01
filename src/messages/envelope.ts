import {
  createCipheriv,
  createDecipheriv,
  createHash,
  privateDecrypt,
  publicEncrypt,
  constants as CryptoConst,
} from "node:crypto";
import { ed25519Sign, ed25519Verify, random } from "./cryptosuite.ts";

export type Envelope = {
  v: 3;
  alg: {
    enc: "RSA-OAEP-256";
    sym: "AES-256-CBC-PKCS7";
    hash: "SHA-256";
    sig: "Ed25519";
  };
  // Chave publica do remetente, usada para verificar a assinatura (Ed25519)
  senderSigPubPem: string;

  // Mensagens AES
  iv_msg_b64: string;
  ct_msg_b64: string;

  // Chave simetrica do AES, cifrada com a publica do remetente (RSA)
  enc_symkey_b64: string;

  // Autenticidade e Integridade
  hash_b64: string;   // Hash SHA-256 enviado pelo remetente
  sig_b64: string;    // Assinatura gerada em cima do Hash (Ed25519)
};

const b64 = (buf: Uint8Array | Buffer) => Buffer.from(buf).toString("base64");
const ub64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
const utf8 = (s: string) => new TextEncoder().encode(s);
const deutf8 = (u: Uint8Array | Buffer) => new TextDecoder().decode(u);

function aes256cbcEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array) {
  const c = createCipheriv("aes-256-cbc", Buffer.from(key), Buffer.from(iv));
  c.setAutoPadding(true); // PKCS#7
  return Buffer.concat([c.update(data), c.final()]);
}
function aes256cbcDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array) {
  const d = createDecipheriv("aes-256-cbc", Buffer.from(key), Buffer.from(iv));
  d.setAutoPadding(true); // PKCS#7
  return Buffer.concat([d.update(data), d.final()]);
}

export function createEnvelope(opts: {
  plaintextUtf8: string;
  senderSigPrivPem: string;  // Ed25519 privada (PEM)
  senderSigPubPem: string;   // Ed25519 publica (PEM)
  recipientEncPubPem: string; // RSA publica (PEM)
}): Envelope {
  const pt = utf8(opts.plaintextUtf8);

  // Hash (SHA-256)
  const hash = createHash("sha256").update(pt).digest();

  // Assina o Hash com nossa chave privada (Ed25519)
  const sig = ed25519Sign(hash, opts.senderSigPrivPem);

  // Cifrar a mensagem com uma chave simetrica e um IV (AES)
  const symKey = random(32);
  const ivMsg = random(16);
  const ctMsg = aes256cbcEncrypt(symKey, ivMsg, pt);

  // Usar a chave publica do destinatario para cifrar nossa chave simetrica (RSA-OAEP-256)
  const encSymKey = publicEncrypt(
    { key: opts.recipientEncPubPem, padding: CryptoConst.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    symKey
  );

  try {
    console.log("\n", "=== MENSAGEM ENVIADA ===")
    console.log("REM destinatarioChavePublica.pem=\n" + opts.recipientEncPubPem.trim(), "\n");
    console.log("REM remetenteChavePublica.pem   =\n" + opts.senderSigPubPem.trim(), "\n");
    console.log("REM remetenteChavePrivada.pem   =\n" + opts.senderSigPrivPem.trim(), "\n");
    console.log("REM chaveSimetrica.b64          =", b64(symKey));
    console.log("REM sha256(mensagem).b64        =", b64(hash));
    console.log("REM sig(hash).b64               =", b64(sig));
    console.log("REM ivMensagem                  =", b64(ivMsg));
    console.log("REM enc(symKey).b64             =", b64(encSymKey));
    console.log("REM enc(mensagem).b64           =", b64(ctMsg));
    console.log("REM mensagemOriginal            =", opts.plaintextUtf8);
    console.log("========================", "\n")
  } catch { }

  return {
    v: 3,
    alg: { enc: "RSA-OAEP-256", sym: "AES-256-CBC-PKCS7", hash: "SHA-256", sig: "Ed25519" },
    senderSigPubPem: opts.senderSigPubPem,
    iv_msg_b64: b64(ivMsg),
    ct_msg_b64: b64(ctMsg),
    enc_symkey_b64: b64(encSymKey),
    hash_b64: b64(hash),
    sig_b64: b64(sig),
  };
}

export function openEnvelope(
  env: Envelope,
  recipientEncPrivPem: string, // RSA privada (PEM)
  recipientEncPubPem: string   // RSA publica (PEM)
): string {
  // Decodificar os campos de base64 para bytes
  const ivMsg = ub64(env.iv_msg_b64);
  const ctMsg = ub64(env.ct_msg_b64);
  const encSymKey = ub64(env.enc_symkey_b64);
  const senderHash = ub64(env.hash_b64);
  const sig = ub64(env.sig_b64);

  // Recuperar a chave AES usando nossa chave privada.
  const symKey = privateDecrypt(
    { key: recipientEncPrivPem, padding: CryptoConst.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(encSymKey)
  );

  // Decifrar com a chave AES
  const pt = aes256cbcDecrypt(symKey, ivMsg, ctMsg);

  // Validar a assinatura do remetente no hash
  const sigValid = ed25519Verify(senderHash, env.senderSigPubPem, sig);

  // Calcular o hash localmente e comparar com o hash do remetente
  const hashRecalc = createHash("sha256").update(pt).digest();
  const hashesMatch = Buffer.compare(senderHash, hashRecalc) === 0;

  try {
    console.log("\n", "=== MENSAGEM RECEBIDA ===")
    console.log("DES destinatarioChavePublica.pem=\n" + recipientEncPubPem.trim(), "\n");
    console.log("DES destinatarioChavePrivada.pem=\n" + recipientEncPrivPem.trim(), "\n");
    console.log("DES remetenteChavePublica.pem   =\n" + env.senderSigPubPem.trim(), "\n");
    console.log("DES chaveSimetrica.b64          =", b64(symKey));
    console.log("DES hashEnviado.b64             =", env.hash_b64);
    console.log("DES sig(hash).b64               =", env.sig_b64);
    console.log("DES hashComputado.b64           =", b64(hashRecalc));
    console.log("DES assinaturaValida?           =", sigValid);
    console.log("DES hashValido?                 =", hashesMatch);
    console.log("DES dec(mensagem)               =", deutf8(pt));
    console.log("=========================", "\n")
  } catch { }

  if (!sigValid) throw new Error("Falha na verificação da assinatura.");
  if (!hashesMatch) throw new Error("Hash não corresponde (mensagem alterada ou corrompida)");

  return deutf8(pt);
}

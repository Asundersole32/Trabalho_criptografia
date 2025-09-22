import { type Bytes, type Mode, assertMultipleOf } from "./util.ts";

export interface BlockCipher {
  readonly blockSize: number;
  /** Encrypt exactly one block (blockSize bytes) */
  encryptBlock(inp: Bytes, inOff: number, out: Bytes, outOff: number): void;
  /** Decrypt exactly one block (blockSize bytes) */
  decryptBlock(inp: Bytes, inOff: number, out: Bytes, outOff: number): void;
}

/** ECB: raw, no padding, length must be multiple of block size */
export function ecbEncryptRaw(cipher: BlockCipher, data: Bytes): Bytes {
  assertMultipleOf(data.length, cipher.blockSize, "Plaintext");
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += cipher.blockSize) {
    cipher.encryptBlock(data, i, out, i);
  }
  return out;
}

export function ecbDecryptRaw(cipher: BlockCipher, data: Bytes): Bytes {
  assertMultipleOf(data.length, cipher.blockSize, "Ciphertext");
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += cipher.blockSize) {
    cipher.decryptBlock(data, i, out, i);
  }
  return out;
}

/** CBC: raw, no padding */
export function cbcEncryptRaw(
  cipher: BlockCipher,
  data: Bytes,
  iv: Bytes
): Bytes {
  const bs = cipher.blockSize;
  if (iv.length !== bs) throw new Error(`IV must be ${bs} bytes`);
  assertMultipleOf(data.length, bs, "Plaintext");

  const out = new Uint8Array(data.length);
  const prev = iv.slice();
  const tmp = new Uint8Array(bs);

  for (let i = 0; i < data.length; i += bs) {
    for (let j = 0; j < bs; j++) tmp[j] = data[i + j] ^ prev[j];
    cipher.encryptBlock(tmp, 0, out, i);
    prev.set(out.subarray(i, i + bs));
  }
  return out;
}

export function cbcDecryptRaw(
  cipher: BlockCipher,
  data: Bytes,
  iv: Bytes
): Bytes {
  const bs = cipher.blockSize;
  if (iv.length !== bs) throw new Error(`IV must be ${bs} bytes`);
  assertMultipleOf(data.length, bs, "Ciphertext");

  const out = new Uint8Array(data.length);
  const prev = iv.slice();
  const tmp = new Uint8Array(bs);

  for (let i = 0; i < data.length; i += bs) {
    cipher.decryptBlock(data, i, tmp, 0);
    for (let j = 0; j < bs; j++) out[i + j] = tmp[j] ^ prev[j];
    prev.set(data.subarray(i, i + bs));
  }
  return out;
}

/** Helper: run a mode by name (raw, no padding). */
export function runModeRaw(
  cipher: BlockCipher,
  mode: Mode,
  data: Bytes,
  iv?: Bytes,
  encrypt = true
): Bytes {
  if (mode === "ECB")
    return encrypt ? ecbEncryptRaw(cipher, data) : ecbDecryptRaw(cipher, data);
  if (!iv) throw new Error("CBC mode requires IV");
  return encrypt
    ? cbcEncryptRaw(cipher, data, iv)
    : cbcDecryptRaw(cipher, data, iv);
}

// -------------- CFB (raw, no padding) -----------------
export function cfbEncryptRaw(
  cipher: BlockCipher,
  data: Bytes,
  iv: Bytes,
  segmentSize = cipher.blockSize // bytes: 1..blockSize
): Bytes {
  if (iv.length !== cipher.blockSize)
    throw new Error(`IV must be ${cipher.blockSize} bytes`);
  if (segmentSize < 1 || segmentSize > cipher.blockSize)
    throw new Error("Bad segmentSize");
  if (data.length % segmentSize !== 0)
    throw new Error("Plaintext must be multiple of segmentSize");

  const out = new Uint8Array(data.length);
  const reg = iv.slice();
  const ks = new Uint8Array(cipher.blockSize);

  for (let i = 0; i < data.length; i += segmentSize) {
    cipher.encryptBlock(reg, 0, ks, 0);
    for (let j = 0; j < segmentSize; j++) out[i + j] = data[i + j]! ^ ks[j]!;
    // shift register: drop left, append ciphertext segment
    reg.copyWithin(0, segmentSize);
    reg.set(out.subarray(i, i + segmentSize), cipher.blockSize - segmentSize);
  }
  return out;
}
export function cfbDecryptRaw(
  cipher: BlockCipher,
  data: Bytes,
  iv: Bytes,
  segmentSize = cipher.blockSize
): Bytes {
  if (iv.length !== cipher.blockSize)
    throw new Error(`IV must be ${cipher.blockSize} bytes`);
  if (segmentSize < 1 || segmentSize > cipher.blockSize)
    throw new Error("Bad segmentSize");
  if (data.length % segmentSize !== 0)
    throw new Error("Ciphertext must be multiple of segmentSize");

  const out = new Uint8Array(data.length);
  const reg = iv.slice();
  const ks = new Uint8Array(cipher.blockSize);

  for (let i = 0; i < data.length; i += segmentSize) {
    cipher.encryptBlock(reg, 0, ks, 0);
    for (let j = 0; j < segmentSize; j++) out[i + j] = data[i + j]! ^ ks[j]!;
    reg.copyWithin(0, segmentSize);
    reg.set(data.subarray(i, i + segmentSize), cipher.blockSize - segmentSize);
  }
  return out;
}

// -------------- OFB (raw, no padding; symmetric) ------
export function ofbXorRaw(cipher: BlockCipher, data: Bytes, iv: Bytes): Bytes {
  if (iv.length !== cipher.blockSize)
    throw new Error(`IV must be ${cipher.blockSize} bytes`);
  const out = new Uint8Array(data.length);
  const reg = iv.slice();
  const ks = new Uint8Array(cipher.blockSize);
  let idx = cipher.blockSize; // force first refill
  for (let i = 0; i < data.length; i++) {
    if (idx === cipher.blockSize) {
      cipher.encryptBlock(reg, 0, ks, 0);
      reg.set(ks); // next precipher = last keystream
      idx = 0;
    }
    out[i] = data[i]! ^ ks[idx++]!;
  }
  return out;
}

// -------------- CTR (raw, no padding; symmetric) ------
function incrementBE(counter: Uint8Array) {
  for (let i = counter.length - 1; i >= 0; i--) {
    const x = (counter[i] + 1) & 0xff;
    counter[i] = x;
    if (x !== 0) break;
  }
}
export function ctrXorRaw(
  cipher: BlockCipher,
  data: Bytes,
  counter: Bytes // initial counter value (length == blockSize)
): Bytes {
  if (counter.length !== cipher.blockSize) {
    throw new Error(`Counter must be ${cipher.blockSize} bytes`);
  }
  const out = new Uint8Array(data.length);
  const ctr = counter.slice();
  const ks = new Uint8Array(cipher.blockSize);
  let idx = cipher.blockSize;

  for (let i = 0; i < data.length; i++) {
    if (idx === cipher.blockSize) {
      cipher.encryptBlock(ctr, 0, ks, 0);
      incrementBE(ctr);
      idx = 0;
    }
    out[i] = data[i]! ^ ks[idx++]!;
  }
  return out;
}

import { type Bytes, type Mode, assertMultipleOf } from "./util.ts";

// modes.ts
function cloneBytes(b: Bytes): Uint8Array {
  const out = new Uint8Array(b.length);
  out.set(b);
  return out;
}

export interface BlockCipher {
  readonly blockSize: number;
  /** Cifrar exatamente um bloco (blockSize bytes) */
  encryptBlock(inp: Bytes, inOff: number, out: Bytes, outOff: number): void;
  /** Decifrar exatamente um bloco (blockSize bytes) */
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

export function ecbEncryptInplaceRaw(
  cipher: BlockCipher,
  data: Bytes,
  out: Uint8Array
): Uint8Array {
  assertMultipleOf(data.length, cipher.blockSize, "Plaintext");
  if (out.length !== data.length)
    throw new Error("Output buffer length must equal input length");
  const bs = cipher.blockSize;

  // If out === data, use a scratch block to avoid aliasing hazards.
  if (out === (data as any)) {
    const tmp = new Uint8Array(bs);
    for (let i = 0; i < data.length; i += bs) {
      tmp.set((data as Uint8Array).subarray(i, i + bs));
      cipher.encryptBlock(tmp, 0, out, i);
    }
  } else {
    for (let i = 0; i < data.length; i += bs) {
      cipher.encryptBlock(data, i, out, i);
    }
  }
  return out;
}

export function ecbDecryptInplaceRaw(
  cipher: BlockCipher,
  data: Bytes,
  out: Uint8Array
): Uint8Array {
  assertMultipleOf(data.length, cipher.blockSize, "Ciphertext");
  if (out.length !== data.length)
    throw new Error("Output buffer length must equal input length");
  const bs = cipher.blockSize;

  if (out === (data as any)) {
    const tmp = new Uint8Array(bs);
    for (let i = 0; i < data.length; i += bs) {
      tmp.set((data as Uint8Array).subarray(i, i + bs));
      cipher.decryptBlock(tmp, 0, out, i);
    }
  } else {
    for (let i = 0; i < data.length; i += bs) {
      cipher.decryptBlock(data, i, out, i);
    }
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
  const prev = cloneBytes(iv);
  const tmp = new Uint8Array(bs);

  for (let i = 0; i < data.length; i += bs) {
    for (let j = 0; j < bs; j++) tmp[j] = data[i + j] ^ prev[j];
    cipher.encryptBlock(tmp, 0, out, i);
    prev.set(out.subarray(i, i + bs)); // update register
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
  const prev = cloneBytes(iv);
  const tmp = new Uint8Array(bs);

  for (let i = 0; i < data.length; i += bs) {
    cipher.decryptBlock(data, i, tmp, 0);
    for (let j = 0; j < bs; j++) out[i + j] = tmp[j] ^ prev[j];
    prev.set(data.subarray(i, i + bs));
  }
  return out;
}

export function cbcEncryptInplaceRaw(
  cipher: BlockCipher,
  data: Bytes,
  iv: Bytes,
  out: Uint8Array
): Uint8Array {
  const bs = cipher.blockSize;
  if (iv.length !== bs) throw new Error(`IV must be ${bs} bytes`);
  assertMultipleOf(data.length, bs, "Plaintext");
  if (out.length !== data.length)
    throw new Error("Output buffer length must equal input length");

  const prev = cloneBytes(iv);
  const tmpXor = new Uint8Array(bs); // one scratch block reused

  for (let i = 0; i < data.length; i += bs) {
    for (let j = 0; j < bs; j++) tmpXor[j] = data[i + j] ^ prev[j];
    cipher.encryptBlock(tmpXor, 0, out, i);
    // update CBC register with just-produced ciphertext
    prev.set(out.subarray(i, i + bs));
  }
  return out;
}

export function cbcDecryptInplaceRaw(
  cipher: BlockCipher,
  data: Bytes,
  iv: Bytes,
  out: Uint8Array
): Uint8Array {
  const bs = cipher.blockSize;
  if (iv.length !== bs) throw new Error(`IV must be ${bs} bytes`);
  assertMultipleOf(data.length, bs, "Ciphertext");
  if (out.length !== data.length)
    throw new Error("Output buffer length must equal input length");

  const prev = cloneBytes(iv);
  const tmpDec = new Uint8Array(bs); // decrypted block
  const tmpCt = new Uint8Array(bs); // saved ciphertext for next prev

  for (let i = 0; i < data.length; i += bs) {
    tmpCt.set((data as Uint8Array).subarray(i, i + bs)); // save CT
    cipher.decryptBlock(data, i, tmpDec, 0);
    for (let j = 0; j < bs; j++) out[i + j] = tmpDec[j] ^ prev[j];
    prev.set(tmpCt); // advance CBC register
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
  segmentSize = cipher.blockSize
): Bytes {
  if (iv.length !== cipher.blockSize)
    throw new Error(`IV must be ${cipher.blockSize} bytes`);
  if (segmentSize < 1 || segmentSize > cipher.blockSize)
    throw new Error("Bad segmentSize");
  if (data.length % segmentSize !== 0)
    throw new Error("Plaintext must be multiple of segmentSize");

  const out = new Uint8Array(data.length);
  const reg = cloneBytes(iv);
  const ks = new Uint8Array(cipher.blockSize);

  for (let i = 0; i < data.length; i += segmentSize) {
    cipher.encryptBlock(reg, 0, ks, 0);
    for (let j = 0; j < segmentSize; j++) out[i + j] = data[i + j]! ^ ks[j]!;
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
  const reg = cloneBytes(iv);
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
  const reg = cloneBytes(iv);
  const ks = new Uint8Array(cipher.blockSize);
  let idx = cipher.blockSize; // force first refill

  for (let i = 0; i < data.length; i++) {
    if (idx === cipher.blockSize) {
      cipher.encryptBlock(reg, 0, ks, 0);
      reg.set(ks);
      idx = 0;
    }
    out[i] = data[i]! ^ ks[idx++]!;
  }
  return out;
}

// -------------- CTR (raw, no padding; symmetric) ------
export function ctrXorRaw(
  cipher: BlockCipher,
  data: Bytes,
  counter: Bytes
): Bytes {
  if (counter.length !== cipher.blockSize)
    throw new Error(`Counter must be ${cipher.blockSize} bytes`);
  const out = new Uint8Array(data.length);
  const ctr = cloneBytes(counter);
  const ks = new Uint8Array(cipher.blockSize);
  let idx = cipher.blockSize;

  for (let i = 0; i < data.length; i++) {
    if (idx === cipher.blockSize) {
      cipher.encryptBlock(ctr, 0, ks, 0);
      // increment ctr (big-endian)...
      for (let j = ctr.length - 1; j >= 0; j--) {
        const x = (ctr[j] + 1) & 0xff;
        ctr[j] = x;
        if (x !== 0) break;
      }
      idx = 0;
    }
    out[i] = data[i]! ^ ks[idx++]!;
  }
  return out;
}

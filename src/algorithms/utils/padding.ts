import type { Bytes } from "./util.ts";

/** PKCS#7 pad/unpad for any block size (8 for Blowfish, 16 for Twofish) */
export function pkcs7Pad(data: Bytes, blockSize: number): Bytes {
  if (!Number.isInteger(blockSize) || blockSize < 1 || blockSize > 255) {
    throw new Error("Invalid block size");
  }
  const len = data.length;
  const rem = len % blockSize;
  const padLen = rem === 0 ? blockSize : blockSize - rem; // 1..blockSize

  const out = new Uint8Array(len + padLen);
  out.set(data, 0);
  out.fill(padLen, len); // fill trailing bytes with pad value
  return out;
}

export function pkcs7Unpad(data: Bytes, blockSize: number): Bytes {
  if (!Number.isInteger(blockSize) || blockSize < 1 || blockSize > 255) {
    throw new Error("Invalid block size");
  }
  const len = data.length;
  if (len === 0 || len % blockSize !== 0) {
    throw new Error("Bad input length");
  }

  const padLen = data[len - 1];
  if (padLen < 1 || padLen > blockSize) {
    throw new Error("Bad padding");
  }

  // Fixed-iteration check over the last block.
  let mismatch = 0;
  for (let i = 0; i < blockSize; i++) {
    const idx = len - 1 - i; // walk backward over last block
    const mask = i < padLen ? 0xff : 0x00;
    mismatch |= (data[idx] ^ padLen) & mask;
  }
  if (mismatch !== 0) {
    throw new Error("Bad padding");
  }

  // Return a copy of the unpadded data
  return data.slice(0, len - padLen);
}

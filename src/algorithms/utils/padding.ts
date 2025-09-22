import { Bytes } from "./util";

/** PKCS#7 pad/unpad for any block size (8 for Blowfish, 16 for Twofish) */
export function pkcs7Pad(data: Bytes, blockSize: number): Bytes {
  if (blockSize < 1 || blockSize > 255) throw new Error("Invalid block size");
  const padLen = blockSize - (data.length % blockSize || blockSize);
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out.fill(padLen, data.length);
  return out;
}

export function pkcs7Unpad(data: Bytes, blockSize: number): Bytes {
  if (data.length === 0 || data.length % blockSize !== 0)
    throw new Error("Bad input");
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > blockSize) throw new Error("Bad padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Bad padding");
  }
  return data.subarray(0, data.length - padLen);
}

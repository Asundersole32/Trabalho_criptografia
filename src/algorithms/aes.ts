// aes.ts
// MIT-style, Node-only, TypeScript port of a manual AES implementation.
// - No Node 'crypto' usage (pure JS math).
// - Exposes AES block cipher, modes (ECB/CBC/CFB/OFB/CTR), PKCS#7, and hex/utf8 utils.
// - Simpler than T-table variants (uses classic SubBytes/ShiftRows/MixColumns).
// - API shape mirrors the original aes-js surface (enough to be a drop-in for most uses).

// ---------- Types & Helpers ----------

export type ByteLike = Uint8Array | number[] | ArrayLike<number> | Buffer;

function isInt(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n);
}

function isByteArrayLike(a: any): a is ArrayLike<number> {
  if (!a || typeof a.length !== "number" || !Number.isInteger(a.length))
    return false;
  for (let i = 0; i < a.length; i++) {
    const v = a[i];
    if (!isInt(v) || v < 0 || v > 255) return false;
  }
  return true;
}

function coerceArray(arg: ByteLike, copy = false): Uint8Array {
  if (arg instanceof Uint8Array) return copy ? new Uint8Array(arg) : arg;
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(arg))
    return new Uint8Array(copy ? Buffer.from(arg) : arg);
  if (Array.isArray(arg)) {
    if (!isByteArrayLike(arg)) throw new Error("Array contains invalid value");
    return new Uint8Array(arg);
  }
  if (isByteArrayLike(arg)) {
    return new Uint8Array(Array.prototype.slice.call(arg));
  }
  throw new Error("unsupported array-like object");
}

function createArray(length: number): Uint8Array {
  return new Uint8Array(length);
}

function copyArray(
  sourceArray: ArrayLike<number>,
  targetArray: Uint8Array,
  targetStart = 0,
  sourceStart = 0,
  sourceEnd?: number
) {
  const src =
    sourceStart != null || sourceEnd != null
      ? new Uint8Array(
          Array.prototype.slice.call(sourceArray, sourceStart, sourceEnd)
        )
      : new Uint8Array(sourceArray as any);
  targetArray.set(src, targetStart);
}

function checkBlock16(b: ArrayLike<number>, what: "plaintext" | "ciphertext") {
  if (b.length !== 16)
    throw new Error(`invalid ${what} size (must be 16 bytes)`);
}

// ---------- UTF-8 / HEX utils (Node-friendly) ----------

export const utils = {
  utf8: {
    toBytes(text: string): Uint8Array {
      if (typeof Buffer !== "undefined")
        return new Uint8Array(Buffer.from(text, "utf8"));
      // very old runtimes: fallback
      return new TextEncoder().encode(text);
    },
    fromBytes(bytes: ByteLike): string {
      const u8 = coerceArray(bytes);
      if (typeof Buffer !== "undefined")
        return Buffer.from(u8).toString("utf8");
      return new TextDecoder().decode(u8);
    },
  },
  hex: {
    toBytes(hex: string): Uint8Array {
      if (hex.length % 2 !== 0)
        throw new Error("hex string must have an even length");
      const out = createArray(hex.length / 2);
      for (let i = 0; i < out.length; i++) {
        const v = parseInt(hex.substr(i * 2, 2), 16);
        if (Number.isNaN(v)) throw new Error("invalid hex");
        out[i] = v;
      }
      return out;
    },
    fromBytes(bytes: ByteLike): string {
      const u8 = coerceArray(bytes);
      let s = "";
      for (let i = 0; i < u8.length; i++)
        s += u8[i]!.toString(16).padStart(2, "0");
      return s;
    },
  },
};

// ---------- PKCS#7 Padding ----------

function pkcs7pad(data: ByteLike): Uint8Array {
  const u8 = coerceArray(data, true);
  const pad = 16 - ((u8.length % 16 || 16) % 16) || 16; // yields 16 when already aligned
  const out = createArray(u8.length + pad);
  copyArray(u8, out);
  out.fill(pad, u8.length);
  return out;
}

function pkcs7strip(data: ByteLike): Uint8Array {
  const u8 = coerceArray(data, true);
  if (u8.length < 16) throw new Error("PKCS#7 invalid length");
  const pad = u8[u8.length - 1]!;
  if (pad < 1 || pad > 16) throw new Error("PKCS#7 padding byte out of range");
  const cut = u8.length - pad;
  for (let i = 0; i < pad; i++) {
    if (u8[cut + i] !== pad) throw new Error("PKCS#7 invalid padding byte");
  }
  return u8.slice(0, cut);
}

export const padding = {
  pkcs7: { pad: pkcs7pad, strip: pkcs7strip },
};

// ---------- AES S-boxes & Rcon (manual, compact) ----------

// Forward S-box
const S: number[] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
  0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
  0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
  0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
  0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
  0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
  0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
  0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
  0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
  0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
  0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
  0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
  0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
  0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Inverse S-box
const Si: number[] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
  0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
  0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23,
  0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
  0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72,
  0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
  0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46,
  0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
  0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
  0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
  0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
  0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f,
  0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
  0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93,
  0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
  0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
  0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Round constants (enough for 256-bit keys)
const RCON: number[] = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
  0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
  0xfa, 0xef, 0xc5, 0x91,
];

// ---------- AES math helpers ----------

function xtime(a: number): number {
  a <<= 1;
  return (a & 0x100 ? a ^ 0x11b : a) & 0xff;
}

function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

// ---------- AES core (manual) ----------

export class AES {
  readonly key: Uint8Array;
  private readonly Nr: number;
  private readonly roundKeys: Uint8Array[]; // 16 bytes per round (Nr+1)

  constructor(key: ByteLike) {
    this.key = coerceArray(key, true);
    const len = this.key.length;
    if (len !== 16 && len !== 24 && len !== 32) {
      throw new Error("invalid key size (must be 16, 24 or 32 bytes)");
    }
    const Nk = len / 4;
    this.Nr = Nk + 6;
    this.roundKeys = this.expandKey(this.key, Nk, this.Nr);
  }

  private expandKey(key: Uint8Array, Nk: number, Nr: number): Uint8Array[] {
    // words (32-bit) total: Nb*(Nr+1) with Nb=4
    const Nb = 4;
    const totalWords = Nb * (Nr + 1);
    const w = new Uint32Array(totalWords);

    // helper to pack 4 bytes into big-endian word
    const pack = (a: number, b: number, c: number, d: number) =>
      ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

    // initial words from key
    for (let i = 0; i < Nk; i++) {
      const j = 4 * i;
      w[i] = pack(key[j], key[j + 1], key[j + 2], key[j + 3]);
    }

    const subWord = (x: number) =>
      ((S[(x >>> 24) & 0xff] << 24) |
        (S[(x >>> 16) & 0xff] << 16) |
        (S[(x >>> 8) & 0xff] << 8) |
        S[x & 0xff]) >>>
      0;

    const rotWord = (x: number) => ((x << 8) | (x >>> 24)) >>> 0;

    // expand
    for (let i = Nk, rconIdx = 0; i < totalWords; i++) {
      let temp = w[i - 1];
      if (i % Nk === 0) {
        temp = subWord(rotWord(temp)) ^ (RCON[rconIdx++] << 24);
      } else if (Nk > 6 && i % Nk === 4) {
        temp = subWord(temp);
      }
      w[i] = (w[i - Nk] ^ temp) >>> 0;
    }

    // Convert to round keys as 16-byte blocks
    const rks: Uint8Array[] = [];
    for (let r = 0; r <= Nr; r++) {
      const block = createArray(16);
      for (let c = 0; c < 4; c++) {
        const word = w[r * 4 + c];
        block[c * 4 + 0] = (word >>> 24) & 0xff;
        block[c * 4 + 1] = (word >>> 16) & 0xff;
        block[c * 4 + 2] = (word >>> 8) & 0xff;
        block[c * 4 + 3] = word & 0xff;
      }
      rks.push(block);
    }
    return rks;
  }

  private addRoundKey(state: Uint8Array, round: number) {
    const rk = this.roundKeys[round];
    for (let i = 0; i < 16; i++) state[i] ^= rk[i]!;
  }

  private subBytes(state: Uint8Array) {
    for (let i = 0; i < 16; i++) state[i] = S[state[i]!]!;
  }

  private invSubBytes(state: Uint8Array) {
    for (let i = 0; i < 16; i++) state[i] = Si[state[i]!]!;
  }

  private shiftRows(state: Uint8Array) {
    // rows are indices [r + 4*c], r in 0..3
    // Row 1: [1,5,9,13] -> [5,9,13,1]
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t!;
    // Row 2: [2,6,10,14] -> [10,14,2,6]
    t = state[2];
    const t2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t!;
    state[14] = t2!;
    // Row 3: [3,7,11,15] -> [15,3,7,11]
    t = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t!;
  }

  private invShiftRows(state: Uint8Array) {
    // Row 1: [1,5,9,13] <- [13,1,5,9]
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t!;
    // Row 2: [2,6,10,14] <- [10,14,2,6] (same as forward)
    t = state[2];
    const t2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t!;
    state[14] = t2!;
    // Row 3: [3,7,11,15] <- [7,11,15,3]
    t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t!;
  }

  private mixColumns(state: Uint8Array) {
    for (let c = 0; c < 16; c += 4) {
      const a0 = state[c],
        a1 = state[c + 1],
        a2 = state[c + 2],
        a3 = state[c + 3];
      state[c] = (gfMul(a0!, 2) ^ gfMul(a1!, 3) ^ a2! ^ a3!) & 0xff;
      state[c + 1] = (a0! ^ gfMul(a1!, 2) ^ gfMul(a2!, 3) ^ a3!) & 0xff;
      state[c + 2] = (a0! ^ a1! ^ gfMul(a2!, 2) ^ gfMul(a3!, 3)) & 0xff;
      state[c + 3] = (gfMul(a0!, 3) ^ a1! ^ a2! ^ gfMul(a3!, 2)) & 0xff;
    }
  }

  private invMixColumns(state: Uint8Array) {
    for (let c = 0; c < 16; c += 4) {
      const a0 = state[c],
        a1 = state[c + 1],
        a2 = state[c + 2],
        a3 = state[c + 3];
      state[c] =
        (gfMul(a0!, 14) ^ gfMul(a1!, 11) ^ gfMul(a2!, 13) ^ gfMul(a3!, 9)) &
        0xff;
      state[c + 1] =
        (gfMul(a0!, 9) ^ gfMul(a1!, 14) ^ gfMul(a2!, 11) ^ gfMul(a3!, 13)) &
        0xff;
      state[c + 2] =
        (gfMul(a0!, 13) ^ gfMul(a1!, 9) ^ gfMul(a2!, 14) ^ gfMul(a3!, 11)) &
        0xff;
      state[c + 3] =
        (gfMul(a0!, 11) ^ gfMul(a1!, 13) ^ gfMul(a2!, 9) ^ gfMul(a3!, 14)) &
        0xff;
    }
  }

  encrypt(plaintext: ByteLike): Uint8Array {
    const p = coerceArray(plaintext);
    checkBlock16(p, "plaintext");
    const s = new Uint8Array(p); // state
    this.addRoundKey(s, 0);
    for (let r = 1; r < this.Nr; r++) {
      this.subBytes(s);
      this.shiftRows(s);
      this.mixColumns(s);
      this.addRoundKey(s, r);
    }
    this.subBytes(s);
    this.shiftRows(s);
    this.addRoundKey(s, this.Nr);
    return s;
  }

  decrypt(ciphertext: ByteLike): Uint8Array {
    const c = coerceArray(ciphertext);
    checkBlock16(c, "ciphertext");
    const s = new Uint8Array(c);
    this.addRoundKey(s, this.Nr);
    for (let r = this.Nr - 1; r >= 1; r--) {
      this.invShiftRows(s);
      this.invSubBytes(s);
      this.addRoundKey(s, r);
      this.invMixColumns(s);
    }
    this.invShiftRows(s);
    this.invSubBytes(s);
    this.addRoundKey(s, 0);
    return s;
  }
}

// ---------- Modes ----------

export class ModeOfOperationECB {
  readonly description = "Electronic Code Block";
  readonly name = "ecb";
  private readonly _aes: AES;

  constructor(key: ByteLike) {
    this._aes = new AES(key);
  }
  encrypt(plaintext: ByteLike): Uint8Array {
    const p = coerceArray(plaintext);
    if (p.length % 16 !== 0)
      throw new Error("invalid plaintext size (must be multiple of 16 bytes)");
    const out = createArray(p.length);
    const block = createArray(16);
    for (let i = 0; i < p.length; i += 16) {
      copyArray(p, block, 0, i, i + 16);
      const enc = this._aes.encrypt(block);
      out.set(enc, i);
    }
    return out;
  }
  decrypt(ciphertext: ByteLike): Uint8Array {
    const c = coerceArray(ciphertext);
    if (c.length % 16 !== 0)
      throw new Error("invalid ciphertext size (must be multiple of 16 bytes)");
    const out = createArray(c.length);
    const block = createArray(16);
    for (let i = 0; i < c.length; i += 16) {
      copyArray(c, block, 0, i, i + 16);
      const dec = this._aes.decrypt(block);
      out.set(dec, i);
    }
    return out;
  }
}

export class ModeOfOperationCBC {
  readonly description = "Cipher Block Chaining";
  readonly name = "cbc";
  private readonly _aes: AES;
  private _lastCipherblock: Uint8Array;

  constructor(key: ByteLike, iv?: ByteLike) {
    this._aes = new AES(key);
    const ivBytes = iv ? coerceArray(iv, true) : createArray(16);
    if (ivBytes.length !== 16)
      throw new Error("invalid initialation vector size (must be 16 bytes)");
    this._lastCipherblock = ivBytes;
  }

  encrypt(plaintext: ByteLike): Uint8Array {
    const p = coerceArray(plaintext);
    if (p.length % 16 !== 0)
      throw new Error("invalid plaintext size (must be multiple of 16 bytes)");
    const out = createArray(p.length);
    const block = createArray(16);
    for (let i = 0; i < p.length; i += 16) {
      copyArray(p, block, 0, i, i + 16);
      for (let j = 0; j < 16; j++) block[j] ^= this._lastCipherblock[j]!;
      const enc = this._aes.encrypt(block);
      out.set(enc, i);
      this._lastCipherblock = enc;
    }
    return out;
  }

  decrypt(ciphertext: ByteLike): Uint8Array {
    const c = coerceArray(ciphertext);
    if (c.length % 16 !== 0)
      throw new Error("invalid ciphertext size (must be multiple of 16 bytes)");
    const out = createArray(c.length);
    const block = createArray(16);
    for (let i = 0; i < c.length; i += 16) {
      copyArray(c, block, 0, i, i + 16);
      const dec = this._aes.decrypt(block);
      for (let j = 0; j < 16; j++)
        out[i + j] = dec[j]! ^ this._lastCipherblock[j]!;
      // advance IV to current ciphertext block
      this._lastCipherblock = c.slice(i, i + 16);
    }
    return out;
  }
}

export class ModeOfOperationCFB {
  readonly description = "Cipher Feedback";
  readonly name = "cfb";
  private readonly _aes: AES;
  private readonly segmentSize: number; // bytes
  private _shiftRegister: Uint8Array;

  constructor(key: ByteLike, iv?: ByteLike, segmentSize = 1) {
    this._aes = new AES(key);
    const ivBytes = iv ? coerceArray(iv, true) : createArray(16);
    if (ivBytes.length !== 16)
      throw new Error("invalid initialation vector size (must be 16 size)");
    this._shiftRegister = ivBytes;
    if (!isInt(segmentSize) || segmentSize < 1 || segmentSize > 16)
      throw new Error("invalid segmentSize");
    this.segmentSize = segmentSize;
  }

  encrypt(plaintext: ByteLike): Uint8Array {
    const enc = coerceArray(plaintext, true);
    if (enc.length % this.segmentSize !== 0)
      throw new Error("invalid plaintext size (must be segmentSize bytes)");
    for (let i = 0; i < enc.length; i += this.segmentSize) {
      const xorSegment = this._aes.encrypt(this._shiftRegister);
      for (let j = 0; j < this.segmentSize; j++) enc[i + j] ^= xorSegment[j]!;
      // shift register: drop left, append ciphertext segment
      this._shiftRegister.copyWithin(0, this.segmentSize, 16);
      this._shiftRegister.set(
        enc.slice(i, i + this.segmentSize),
        16 - this.segmentSize
      );
    }
    return enc;
  }

  decrypt(ciphertext: ByteLike): Uint8Array {
    const c = coerceArray(ciphertext);
    if (c.length % this.segmentSize !== 0)
      throw new Error("invalid ciphertext size (must be segmentSize bytes)");
    const out = coerceArray(c, true);
    for (let i = 0; i < out.length; i += this.segmentSize) {
      const xorSegment = this._aes.encrypt(this._shiftRegister);
      for (let j = 0; j < this.segmentSize; j++) out[i + j] ^= xorSegment[j]!;
      this._shiftRegister.copyWithin(0, this.segmentSize, 16);
      this._shiftRegister.set(
        c.slice(i, i + this.segmentSize),
        16 - this.segmentSize
      );
    }
    return out;
  }
}

export class ModeOfOperationOFB {
  readonly description = "Output Feedback";
  readonly name = "ofb";
  private readonly _aes: AES;
  private _lastPrecipher: Uint8Array;
  private _lastPrecipherIndex = 16;

  constructor(key: ByteLike, iv?: ByteLike) {
    this._aes = new AES(key);
    const ivBytes = iv ? coerceArray(iv, true) : createArray(16);
    if (ivBytes.length !== 16)
      throw new Error("invalid initialation vector size (must be 16 bytes)");
    this._lastPrecipher = ivBytes;
  }

  encrypt(plaintext: ByteLike): Uint8Array {
    const encrypted = coerceArray(plaintext, true);
    for (let i = 0; i < encrypted.length; i++) {
      if (this._lastPrecipherIndex === 16) {
        this._lastPrecipher = this._aes.encrypt(this._lastPrecipher);
        this._lastPrecipherIndex = 0;
      }
      encrypted[i] ^= this._lastPrecipher[this._lastPrecipherIndex++]!;
    }
    return encrypted;
  }

  // symmetric
  decrypt = this.encrypt;
}

export class Counter {
  private _counter: Uint8Array;

  constructor(initialValue?: number | ByteLike) {
    if (initialValue === 0 || initialValue) {
      if (typeof initialValue === "number") {
        this._counter = createArray(16);
        this.setValue(initialValue);
      } else {
        this.setBytes(initialValue);
      }
    } else {
      this._counter = createArray(16);
      this.setValue(1);
    }
  }

  setValue(value: number) {
    if (!isInt(value))
      throw new Error("invalid counter value (must be an integer)");
    if (value > Number.MAX_SAFE_INTEGER)
      throw new Error("integer value out of safe range");
    for (let i = 15; i >= 0; --i) {
      this._counter[i] = value % 256;
      value = Math.floor(value / 256);
    }
  }

  setBytes(bytes: ByteLike) {
    const b = coerceArray(bytes, true);
    if (b.length !== 16)
      throw new Error("invalid counter bytes size (must be 16 bytes)");
    this._counter = b;
  }

  increment() {
    for (let i = 15; i >= 0; i--) {
      if (this._counter[i] === 255) {
        this._counter[i] = 0;
      } else {
        this._counter[i]!++;
        break;
      }
    }
  }

  get value(): Uint8Array {
    return this._counter;
  }
}

export class ModeOfOperationCTR {
  readonly description = "Counter";
  readonly name = "ctr";
  private readonly _aes: AES;
  private readonly _counter: Counter;
  private _remainingCounter: Uint8Array | null = null;
  private _remainingCounterIndex = 16;

  constructor(key: ByteLike, counter?: Counter | number | ByteLike) {
    this._aes = new AES(key);
    this._counter =
      counter instanceof Counter ? counter : new Counter(counter as any);
  }

  encrypt(plaintext: ByteLike): Uint8Array {
    const out = coerceArray(plaintext, true);
    for (let i = 0; i < out.length; i++) {
      if (this._remainingCounterIndex === 16) {
        this._remainingCounter = this._aes.encrypt(this._counter.value);
        this._remainingCounterIndex = 0;
        this._counter.increment();
      }
      out[i] ^= this._remainingCounter![this._remainingCounterIndex++]!;
    }
    return out;
  }

  // symmetric
  decrypt = this.encrypt;
}

// ---------- Namespaced export (like original aesjs) ----------

export const ModeOfOperation = {
  ecb: ModeOfOperationECB,
  cbc: ModeOfOperationCBC,
  cfb: ModeOfOperationCFB,
  ofb: ModeOfOperationOFB,
  ctr: ModeOfOperationCTR,
};

export const _arrayTest = { coerceArray, createArray, copyArray };

const aesjs = {
  AES,
  Counter,
  ModeOfOperation,
  utils,
  padding,
  _arrayTest,
};

export default aesjs;

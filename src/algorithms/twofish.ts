import { P0, P1, MDS0, MDS1, MDS2, MDS3 } from "./utils/constants.ts";
import type { BlockCipher } from "./utils/modes.ts";

// --------------------- IMPLEMENTATION ---------------------

export type Session = [Uint32Array, Uint32Array];

const ROUNDS = 16;
const SK_STEP = 0x01010101;
const SK_ROTL = 9;
const ROUND_SUBKEYS = 8;
const SUBKEY_CNT = 40;
const RS_GF_FDBK = 0x14d;

function b0(x: number) {
  return x & 0xff;
}
function b1(x: number) {
  return (x >>> 8) & 0xff;
}
function b2(x: number) {
  return (x >>> 16) & 0xff;
}
function b3(x: number) {
  return (x >>> 24) & 0xff;
}

function rsMDSEncode(k0: number, k1: number) {
  let b = (k1 >>> 24) & 0xff;
  let g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
  let g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
  k1 = (k1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
  for (let i = 0; i < 3; i++) {
    b = (k1 >>> 24) & 0xff;
    g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
    g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
    k1 = (k1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
  }
  k1 ^= k0;
  for (let i = 0; i < 4; i++) {
    b = (k1 >>> 24) & 0xff;
    g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
    g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
    k1 = (k1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
  }
  return k1;
}

const subKeyWord = new Uint32Array(4);
function getSubKeyWord(
  k64Cnt: number,
  k0: number,
  k1: number,
  k2: number,
  k3: number,
  B0: number,
  B1: number,
  B2: number,
  B3: number
) {
  switch (k64Cnt & 3) {
    case 0: // 256 bit key
      B0 = P1[B0] ^ b0(k3);
      B1 = P0[B1] ^ b1(k3);
      B2 = P0[B2] ^ b2(k3);
      B3 = P1[B3] ^ b3(k3);
    /* falls through */

    case 3: // 192 bit key
      B0 = P1[B0] ^ b0(k2);
      B1 = P1[B1] ^ b1(k2);
      B2 = P0[B2] ^ b2(k2);
      B3 = P0[B3] ^ b3(k2);
    /* falls through */

    case 2: // 128 bit key
      B0 = P0[B0] ^ b0(k1);
      B1 = P1[B1] ^ b1(k1);
      B2 = P0[B2] ^ b2(k1);
      B3 = P1[B3] ^ b3(k1);
    /* falls through */

    default:
    case 1: // 64 bit key
      subKeyWord[0] = MDS0[P0[B0] ^ b0(k0)];
      subKeyWord[1] = MDS1[P0[B1] ^ b1(k0)];
      subKeyWord[2] = MDS2[P1[B2] ^ b2(k0)];
      subKeyWord[3] = MDS3[P1[B3] ^ b3(k0)];
      return;
  }
}

export function makeSession(key: Uint8Array): Session {
  let keyLength = key.length;
  if (keyLength > 32) {
    key = key.subarray(0, 32);
  } else {
    const mod = keyLength & 7;
    if (keyLength === 0 || mod !== 0) {
      keyLength += 8 - mod;
      const nkey = new Uint8Array(keyLength);
      nkey.set(key);
      key = nkey;
    }
  }

  const k64Cnt = keyLength / 8;
  const sessionMemory = new ArrayBuffer(4256);
  const sBox = new Uint32Array(sessionMemory, 0, 1024);

  let offset = 0;

  let k0 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  let k1 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  sBox[k64Cnt - 1] = rsMDSEncode(k0, k1);

  let k2 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  let k3 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  sBox[k64Cnt - 2] = rsMDSEncode(k2, k3);

  const k4 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  const k5 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  sBox[k64Cnt - 3] = rsMDSEncode(k4, k5);

  const k6 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  const k7 =
    key[offset++] |
    (key[offset++] << 8) |
    (key[offset++] << 16) |
    (key[offset++] << 24);
  sBox[k64Cnt - 4] = rsMDSEncode(k6, k7);

  let A: number;
  let B: number;
  const subKeys = new Uint32Array(sessionMemory, 4096, 40);
  for (let i = 0, q = 0, j = 0; i < SUBKEY_CNT / 2; i++, j += 2) {
    getSubKeyWord(k64Cnt, k0, k2, k4, k6, b0(q), b1(q), b2(q), b3(q));
    A = subKeyWord[0] ^ subKeyWord[1] ^ subKeyWord[2] ^ subKeyWord[3];
    q += SK_STEP;

    getSubKeyWord(k64Cnt, k1, k3, k5, k7, b0(q), b1(q), b2(q), b3(q));
    B = subKeyWord[0] ^ subKeyWord[1] ^ subKeyWord[2] ^ subKeyWord[3];
    q += SK_STEP;

    B = (B << 8) | (B >>> 24);

    A += B;
    subKeys[j] = A;

    A += B;
    subKeys[j + 1] = (A << SK_ROTL) | (A >>> (32 - SK_ROTL));
  }

  k0 = sBox[0];
  k1 = sBox[1];
  k2 = sBox[2];
  k3 = sBox[3];

  for (let i = 0, j = 0; i < 256; i++, j += 2) {
    getSubKeyWord(k64Cnt, k0, k1, k2, k3, i, i, i, i);

    sBox[j] = subKeyWord[0];
    sBox[j + 1] = subKeyWord[1];
    sBox[0x200 + j] = subKeyWord[2];
    sBox[0x201 + j] = subKeyWord[3];
  }

  return [sBox, subKeys];
}

function outputBlock(
  out: Uint8Array,
  oo: number,
  x0: number,
  x1: number,
  x2: number,
  x3: number
) {
  out[oo++] = x0;
  out[oo++] = x0 >>> 8;
  out[oo++] = x0 >>> 16;
  out[oo++] = x0 >>> 24;
  out[oo++] = x1;
  out[oo++] = x1 >>> 8;
  out[oo++] = x1 >>> 16;
  out[oo++] = x1 >>> 24;
  out[oo++] = x2;
  out[oo++] = x2 >>> 8;
  out[oo++] = x2 >>> 16;
  out[oo++] = x2 >>> 24;
  out[oo++] = x3;
  out[oo++] = x3 >>> 8;
  out[oo++] = x3 >>> 16;
  out[oo++] = x3 >>> 24;
}

export function encrypt(
  plain: Uint8Array,
  io: number,
  cipher: Uint8Array,
  oo: number,
  [sBox, sKey]: Session
) {
  if (cipher.length < oo + 16) {
    throw new Error("Insufficient space to write ciphertext block.");
  }
  let x0 =
    (plain[io++] |
      (plain[io++] << 8) |
      (plain[io++] << 16) |
      (plain[io++] << 24)) ^
    sKey[0];
  let x1 =
    (plain[io++] |
      (plain[io++] << 8) |
      (plain[io++] << 16) |
      (plain[io++] << 24)) ^
    sKey[1];
  let x2 =
    (plain[io++] |
      (plain[io++] << 8) |
      (plain[io++] << 16) |
      (plain[io++] << 24)) ^
    sKey[2];
  let x3 =
    (plain[io++] |
      (plain[io++] << 8) |
      (plain[io++] << 16) |
      (plain[io++] << 24)) ^
    sKey[3];

  let t0: number;
  let t1: number;
  let k = ROUND_SUBKEYS;
  for (let R = 0; R < ROUNDS; R += 2) {
    t0 =
      sBox[(x0 << 1) & 0x1fe] ^
      sBox[((x0 >>> 7) & 0x1fe) + 1] ^
      sBox[0x200 + ((x0 >>> 15) & 0x1fe)] ^
      sBox[0x200 + ((x0 >>> 23) & 0x1fe) + 1];
    t1 =
      sBox[(x1 >>> 23) & 0x1fe] ^
      sBox[((x1 << 1) & 0x1fe) + 1] ^
      sBox[0x200 + ((x1 >>> 7) & 0x1fe)] ^
      sBox[0x200 + ((x1 >>> 15) & 0x1fe) + 1];

    x2 ^= t0 + t1 + sKey[k++];
    x2 = (x2 >>> 1) | (x2 << 31);
    x3 = (x3 << 1) | (x3 >>> 31);
    x3 ^= t0 + 2 * t1 + sKey[k++];

    t0 =
      sBox[(x2 << 1) & 0x1fe] ^
      sBox[((x2 >>> 7) & 0x1fe) + 1] ^
      sBox[0x200 + ((x2 >>> 15) & 0x1fe)] ^
      sBox[0x200 + ((x2 >>> 23) & 0x1fe) + 1];
    t1 =
      sBox[(x3 >>> 23) & 0x1fe] ^
      sBox[((x3 << 1) & 0x1fe) + 1] ^
      sBox[0x200 + ((x3 >>> 7) & 0x1fe)] ^
      sBox[0x200 + ((x3 >>> 15) & 0x1fe) + 1];

    x0 ^= t0 + t1 + sKey[k++];
    x0 = (x0 >>> 1) | (x0 << 31);
    x1 = (x1 << 1) | (x1 >>> 31);
    x1 ^= t0 + 2 * t1 + sKey[k++];
  }

  outputBlock(
    cipher,
    oo,
    x2 ^ sKey[4],
    x3 ^ sKey[5],
    x0 ^ sKey[6],
    x1 ^ sKey[7]
  );
}

export function decrypt(
  cipher: Uint8Array,
  io: number,
  plain: Uint8Array,
  oo: number,
  [sBox, sKey]: Session
) {
  if (cipher.length < io + 16) {
    throw new Error("Incomplete ciphertext block.");
  }
  if (plain.length < oo + 16) {
    throw new Error("Insufficient space to write plaintext block.");
  }
  let x2 =
    (cipher[io++] |
      (cipher[io++] << 8) |
      (cipher[io++] << 16) |
      (cipher[io++] << 24)) ^
    sKey[4];
  let x3 =
    (cipher[io++] |
      (cipher[io++] << 8) |
      (cipher[io++] << 16) |
      (cipher[io++] << 24)) ^
    sKey[5];
  let x0 =
    (cipher[io++] |
      (cipher[io++] << 8) |
      (cipher[io++] << 16) |
      (cipher[io++] << 24)) ^
    sKey[6];
  let x1 =
    (cipher[io++] |
      (cipher[io++] << 8) |
      (cipher[io++] << 16) |
      (cipher[io++] << 24)) ^
    sKey[7];

  let t0: number;
  let t1: number;
  let k = ROUND_SUBKEYS + 2 * ROUNDS - 1;
  for (let R = 0; R < ROUNDS; R += 2) {
    t0 =
      sBox[(x2 << 1) & 0x1fe] ^
      sBox[((x2 >>> 7) & 0x1fe) + 1] ^
      sBox[0x200 + ((x2 >>> 15) & 0x1fe)] ^
      sBox[0x200 + ((x2 >>> 23) & 0x1fe) + 1];
    t1 =
      sBox[(x3 >>> 23) & 0x1fe] ^
      sBox[((x3 << 1) & 0x1fe) + 1] ^
      sBox[0x200 + ((x3 >>> 7) & 0x1fe)] ^
      sBox[0x200 + ((x3 >>> 15) & 0x1fe) + 1];

    x1 ^= t0 + 2 * t1 + sKey[k--];
    x1 = (x1 >>> 1) | (x1 << 31);
    x0 = (x0 << 1) | (x0 >>> 31);
    x0 ^= t0 + t1 + sKey[k--];

    t0 =
      sBox[(x0 << 1) & 0x1fe] ^
      sBox[((x0 >>> 7) & 0x1fe) + 1] ^
      sBox[0x200 + ((x0 >>> 15) & 0x1fe)] ^
      sBox[0x200 + ((x0 >>> 23) & 0x1fe) + 1];
    t1 =
      sBox[(x1 >>> 23) & 0x1fe] ^
      sBox[((x1 << 1) & 0x1fe) + 1] ^
      sBox[0x200 + ((x1 >>> 7) & 0x1fe)] ^
      sBox[0x200 + ((x1 >>> 15) & 0x1fe) + 1];

    x3 ^= t0 + 2 * t1 + sKey[k--];
    x3 = (x3 >>> 1) | (x3 << 31);
    x2 = (x2 << 1) | (x2 >>> 31);
    x2 ^= t0 + t1 + sKey[k--];
  }

  outputBlock(
    plain,
    oo,
    x0 ^ sKey[0],
    x1 ^ sKey[1],
    x2 ^ sKey[2],
    x3 ^ sKey[3]
  );
}

export const tfEncryptBlock = encrypt;
export const tfDecryptBlock = decrypt;

export class TwofishRaw implements BlockCipher {
  readonly blockSize = 16;
  private session: Session;

  constructor(key: Uint8Array) {
    this.session = makeSession(key); // your original function
  }

  encryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    tfEncryptBlock(inp, inOff, out, outOff, this.session);
  }

  decryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    tfDecryptBlock(inp, inOff, out, outOff, this.session);
  }
}

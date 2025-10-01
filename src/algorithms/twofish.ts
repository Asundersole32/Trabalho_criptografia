/*
 * Twofish block cipher — compact TypeScript implementation with explanatory comments.
 *
 * Overview
 * --------
 * - Key schedule generates 40 subkeys (in/out whitening + 32 round subkeys) and a key-dependent S-box table.
 * - Data is processed in 128‑bit blocks (16 bytes). Words are treated as little‑endian 32‑bit unsigned ints.
 * - This file exposes low-level single-block encrypt/decrypt plus a small BlockCipher wrapper.
 *
 * Tables
 * ------
 * P0, P1  : fixed 8×8 permutations from Twofish spec (q-boxes).
 * MDS0..3 : 4 precomputed 256-entry tables representing the 4×4 MDS matrix multiply in GF(2^8) with different byte lanes.
 * RS_GF_FDBK : feedback polynomial used by the Reed–Solomon code that mixes key bytes to build S-box seeds.
 *
 * Session layout (ArrayBuffer of ~4KB)
 * -----------------------------------
 * [0 .. 1023]       : sBox (1024 × u32) — packed lookups used to compute round T-functions quickly.
 * [4096 .. 4096+160): subKeys (40 × u32) — whitening + round subkeys.
 *
 * Security notes (non-functional):
 * - Twofish supports key sizes of 128/192/256 bits. This implementation also accepts 64/96/160/224 after zero‑padding
 *   to a multiple of 64 bits (8 bytes). Zero‑padding an arbitrary key is generally not recommended for new systems;
 *   prefer 16/24/32 byte keys and reject others at the API boundary.
 */

import { P0, P1, MDS0, MDS1, MDS2, MDS3 } from "./utils/constants.ts";
import { b0, b1, b2, b3 } from './utils/util.ts'
import type { BlockCipher } from "./utils/modes.ts";

export type Session = [Uint32Array, Uint32Array];

// Algorithm parameters (fixed for Twofish)
const ROUNDS = 16;             // Twofish has 16 Feistel rounds
const SK_STEP = 0x01010101;    // Key schedule increment for the Q-box input (q in spec)
const SK_ROTL = 9;             // Rotation applied when generating odd subkeys
const ROUND_SUBKEYS = 8;       // Index where round subkeys start (after 8 whitening keys)
const SUBKEY_CNT = 40;         // 8 whitening + 32 round subkeys
const RS_GF_FDBK = 0x14d;      // RS code feedback polynomial (x^8 + x^6 + x^3 + x^2 + 1)


/**
 * rsMDSEncode
 * ----------
 * Mixes 64 bits of key material (k0||k1) using a (12,8) Reed–Solomon code over GF(256),
 * producing a 32-bit value that seeds the key-dependent S-boxes (the S vector in Twofish).
 * Implementation mirrors the reference: iterate 8 steps of LFSR over k1, XOR with k0,
 * then another 4 steps. All operations are bytewise with the RS feedback polynomial.
 */
function rsMDSEncode(k0: number, k1: number) {
  let b = (k1 >>> 24) & 0xff;
  let g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
  let g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
  k1 = (k1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
  for (let i = 0; i < 3; i++) { // total first 4 steps
    b = (k1 >>> 24) & 0xff;
    g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
    g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
    k1 = (k1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
  }
  k1 ^= k0; // mix in lower 32 bits
  for (let i = 0; i < 4; i++) { // and 4 more steps
    b = (k1 >>> 24) & 0xff;
    g2 = ((b << 1) ^ ((b & 0x80) !== 0 ? RS_GF_FDBK : 0)) & 0xff;
    g3 = (b >>> 1) ^ ((b & 0x01) !== 0 ? RS_GF_FDBK >>> 1 : 0) ^ g2;
    k1 = (k1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
  }
  return k1;
}

// Scratch buffer for getSubKeyWord outputs (4 MDS-multiplied words, one per byte lane)
const subKeyWord = new Uint32Array(4);

/**
 * getSubKeyWord
 * -------------
 * Core of Twofish h(x): cascades P-box lookups keyed by up to 256-bit key material
 * and finishes with a 4×4 MDS multiply (via MDS tables) to produce 4 lane words.
 *
 * k64Cnt: number of 64-bit key chunks (1,2,3,4) => 64/128/192/256-bit.
 * k0..k3: 32-bit words from the key (used depending on k64Cnt).
 * B0..B3: input bytes for the q-permutation cascade.
 *
 * On exit, subKeyWord[0..3] contain the four MDS-multiplied lane results.
 */
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
    case 0: // 256-bit key: apply highest key words first
      B0 = P1[B0] ^ b0(k3);
      B1 = P0[B1] ^ b1(k3);
      B2 = P0[B2] ^ b2(k3);
      B3 = P1[B3] ^ b3(k3);
    /* falls through */

    case 3: // 192-bit key
      B0 = P1[B0] ^ b0(k2);
      B1 = P1[B1] ^ b1(k2);
      B2 = P0[B2] ^ b2(k2);
      B3 = P0[B3] ^ b3(k2);
    /* falls through */

    case 2: // 128-bit key
      B0 = P0[B0] ^ b0(k1);
      B1 = P1[B1] ^ b1(k1);
      B2 = P0[B2] ^ b2(k1);
      B3 = P1[B3] ^ b3(k1);
    /* falls through */

    default:
    case 1: // 64-bit key (non-standard but supported by this implementation)
      // Final MDS multiply maps 4 bytes to 4 lane-specific 32-bit words.
      subKeyWord[0] = MDS0[P0[B0] ^ b0(k0)];
      subKeyWord[1] = MDS1[P0[B1] ^ b1(k0)];
      subKeyWord[2] = MDS2[P1[B2] ^ b2(k0)];
      subKeyWord[3] = MDS3[P1[B3] ^ b3(k0)];
      return;
  }
}

/**
 * makeSession(key)
 * ----------------
 * Builds the key schedule: sBox (key-dependent S-box table) and subKeys (whitening + round keys).
 * Accepts a Uint8Array key; trims to 32 bytes and zero‑pads to a multiple of 8 bytes if needed.
 */
export function makeSession(key: Uint8Array): Session {
  let keyLength = key.length;

  // Enforce max 256-bit and pad to a multiple of 64 bits for internal schedule math
  if (keyLength > 32) {
    key = key.subarray(0, 32);
  } else {
    const mod = keyLength & 7;
    if (keyLength === 0 || mod !== 0) {
      keyLength += 8 - mod;
      const nkey = new Uint8Array(keyLength);
      nkey.set(key); // zero-extend
      key = nkey;
    }
  }

  const k64Cnt = keyLength / 8; // number of 64-bit chunks

  // Allocate one backing buffer: first 1024 u32 for S-box, then 40 u32 for subkeys
  const sessionMemory = new ArrayBuffer(4256);
  const sBox = new Uint32Array(sessionMemory, 0, 1024);

  // Read up to 8 words (32 bytes) of key in little-endian order
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
  // S vector components (Twofish): RS-encode each pair of 32-bit words
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

  // Generate whitening and round subkeys
  let A: number;
  let B: number;
  const subKeys = new Uint32Array(sessionMemory, 4096, 40);
  for (let i = 0, q = 0, j = 0; i < SUBKEY_CNT / 2; i++, j += 2) {
    // A = h(q, Me)   (even words)
    getSubKeyWord(k64Cnt, k0, k2, k4, k6, b0(q), b1(q), b2(q), b3(q));
    A = subKeyWord[0] ^ subKeyWord[1] ^ subKeyWord[2] ^ subKeyWord[3];
    q += SK_STEP;

    // B = h(q, Mo)   (odd words)
    getSubKeyWord(k64Cnt, k1, k3, k5, k7, b0(q), b1(q), b2(q), b3(q));
    B = subKeyWord[0] ^ subKeyWord[1] ^ subKeyWord[2] ^ subKeyWord[3];
    q += SK_STEP;

    // Per spec: rotate B by 8 bits before combining
    B = (B << 8) | (B >>> 24);

    // Subkey pair: K[2i] = A + B, K[2i+1] = (A + 2B) <<< 9
    A += B;
    subKeys[j] = A;

    A += B;
    subKeys[j + 1] = (A << SK_ROTL) | (A >>> (32 - SK_ROTL));
  }

  // Prepare the key-dependent S-box tables used inside the T-functions
  k0 = sBox[0];
  k1 = sBox[1];
  k2 = sBox[2];
  k3 = sBox[3];

  // For every possible byte value, precompute h(i) lanes into two 512-entry regions
  for (let i = 0, j = 0; i < 256; i++, j += 2) {
    getSubKeyWord(k64Cnt, k0, k1, k2, k3, i, i, i, i);

    sBox[j] = subKeyWord[0];
    sBox[j + 1] = subKeyWord[1];
    sBox[0x200 + j] = subKeyWord[2];
    sBox[0x201 + j] = subKeyWord[3];
  }

  return [sBox, subKeys];
}

/**
 * outputBlock
 * -----------
 * Writes four 32-bit words to the output buffer in little‑endian order at offset `oo`.
 */
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

/**
 * encrypt
 * -------
 * Encrypts one 16-byte block from `plain` at offset `io` into `cipher` at offset `oo`.
 * Applies input whitening, 16 Feistel rounds (in pairs), and output whitening.
 */
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

  // Load 4 little-endian words and apply input whitening K[0..3]
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

  // T-function temporaries
  let t0: number;
  let t1: number;
  let k = ROUND_SUBKEYS; // start of round subkeys K[8..]

  // Process two rounds per loop (standard optimization)
  for (let R = 0; R < ROUNDS; R += 2) {
    // Compute T(x0) and T(x1). Each T() uses 4 byte-lane lookups from sBox and XORs them.
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

    // Feistel mix into right half (x2,x3) with rotations and round subkeys
    x2 ^= t0 + t1 + sKey[k++];
    x2 = (x2 >>> 1) | (x2 << 31);   // ROR 1
    x3 = (x3 << 1) | (x3 >>> 31);   // ROL 1
    x3 ^= t0 + 2 * t1 + sKey[k++];

    // Next round (roles swap)
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
    x0 = (x0 >>> 1) | (x0 << 31);   // ROR 1
    x1 = (x1 << 1) | (x1 >>> 31);   // ROL 1
    x1 ^= t0 + 2 * t1 + sKey[k++];
  }

  // Output whitening and permutation (x2,x3,x0,x1) per Twofish spec
  outputBlock(
    cipher,
    oo,
    x2 ^ sKey[4],
    x3 ^ sKey[5],
    x0 ^ sKey[6],
    x1 ^ sKey[7]
  );
}

/**
 * decrypt
 * -------
 * Inverse of encrypt(): reads 16 bytes from `cipher` at `io` and writes 16 bytes to `plain` at `oo`.
 * Uses reverse round order and inverse rotations; whitening keys are applied in reverse positions.
 */
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

  // Undo output whitening from encrypt (load x2,x3,x0,x1)
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
  let k = ROUND_SUBKEYS + 2 * ROUNDS - 1; // start from last round subkey

  for (let R = 0; R < ROUNDS; R += 2) {
    // Reverse of the last encryption round pair
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
    x1 = (x1 >>> 1) | (x1 << 31);   // ROR 1 (inverse of ROL 1)
    x0 = (x0 << 1) | (x0 >>> 31);   // ROL 1 (inverse of ROR 1)
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

  // Undo input whitening from encrypt (restore x0..x3 order)
  outputBlock(
    plain,
    oo,
    x0 ^ sKey[0],
    x1 ^ sKey[1],
    x2 ^ sKey[2],
    x3 ^ sKey[3]
  );
}

// Aliases for clarity (mirroring original exports)
export const tfEncryptBlock = encrypt;
export const tfDecryptBlock = decrypt;

// Minimal BlockCipher wrapper around the session for mode code to use
export class TwofishRaw implements BlockCipher {
  readonly blockSize = 16; // bytes
  private session: Session;

  constructor(key: Uint8Array) {
    this.session = makeSession(key);
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

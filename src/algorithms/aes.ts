import type { BlockCipher } from "./utils/modes.ts";
import { S, Si, RCON } from "./utils/constants.ts";

/**
 * Tiny GF(2^8) multiplier used by AES MixColumns.
 * Performs carry-less multiplication modulo x^8 + x^4 + x^3 + x + 1 (0x11B).
 */
function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    // If current bit of b is set, add (XOR) a into the product.
    if (b & 1) p ^= a;
    // Track whether high bit of a is set before left shift (for reduction).
    const hi = a & 0x80;
    // Left shift a (multiply by x), keep it to 8 bits.
    a = (a << 1) & 0xff;
    // If high bit overflowed, reduce modulo AES polynomial (0x1b).
    if (hi) a ^= 0x1b;
    // Move to next bit of b.
    b >>>= 1;
  }
  return p & 0xff;
}

/** Pack 4 bytes into a big-endian 32-bit word (as unsigned). */
const pack = (a: number, b: number, c: number, d: number) =>
  ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

/**
 * Raw AES block cipher (ECB primitive only).
 * - No padding, no modes.
 * - Supports 128/192/256-bit keys.
 */
export class AESRaw implements BlockCipher {
  /** AES block size is always 16 bytes. */
  readonly blockSize = 16;

  /** Number of rounds: 10/12/14 for 128/192/256-bit keys, respectively. */
  private readonly Nr: number;
  /** Round keys (Nr+1 of them), each 16 bytes. */
  private readonly roundKeys: Uint8Array[];

  constructor(key: Uint8Array) {
    const len = key.length;
    if (len !== 16 && len !== 24 && len !== 32) {
      throw new Error("AES key must be 16/24/32 bytes");
    }
    const Nk = len / 4;     // Number of 32-bit words in the key: 4/6/8
    this.Nr = Nk + 6;       // AES rule for rounds: 10/12/14
    this.roundKeys = this.expandKey(key, Nk, this.Nr);
  }

  /**
   * Expand the cipher key into Nb*(Nr+1) words (Nb=4).
   * Produces Nr+1 round-key blocks, each 16 bytes.
   */
  private expandKey(key: Uint8Array, Nk: number, Nr: number): Uint8Array[] {
    const Nb = 4; // AES state width in 32-bit words
    const totalWords = Nb * (Nr + 1); // total expanded words
    const w = new Uint32Array(totalWords);

    // Seed the first Nk words directly from the key bytes.
    for (let i = 0; i < Nk; i++) {
      const j = 4 * i;
      w[i] = pack(key[j], key[j + 1], key[j + 2], key[j + 3]);
    }

    // SubWord and RotWord helpers used in key schedule.
    const subWord = (x: number) =>
      ((S[(x >>> 24) & 0xff] << 24) |
        (S[(x >>> 16) & 0xff] << 16) |
        (S[(x >>> 8) & 0xff] << 8) |
        S[x & 0xff]) >>>
      0;
    const rotWord = (x: number) => ((x << 8) | (x >>> 24)) >>> 0;

    // Key expansion core loop.
    for (let i = Nk, rconIdx = 0; i < totalWords; i++) {
      let temp = w[i - 1];
      if (i % Nk === 0) {
        // Every Nk words: RotWord, SubWord, XOR with Rcon (on MSB).
        temp = subWord(rotWord(temp)) ^ (RCON[rconIdx++] << 24);
      } else if (Nk > 6 && i % Nk === 4) {
        // Extra SubWord step for 256-bit keys.
        temp = subWord(temp);
      }
      // New word is previous Nk-th word XOR transformed temp.
      w[i] = (w[i - Nk] ^ temp) >>> 0;
    }

    // Convert words into round-key byte blocks: (Nr+1) * 16 bytes.
    const rks: Uint8Array[] = [];
    for (let r = 0; r <= Nr; r++) {
      const block = new Uint8Array(16);
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

  /** XOR the state with the round key for the given round. */
  private addRoundKey(state: Uint8Array, round: number) {
    const rk = this.roundKeys[round];
    for (let i = 0; i < 16; i++) state[i] ^= rk[i]!;
  }

  /** Byte-wise S-box substitution. */
  private subBytes(state: Uint8Array) {
    for (let i = 0; i < 16; i++) state[i] = S[state[i]!]!;
  }

  /** Inverse byte-wise S-box substitution. */
  private invSubBytes(state: Uint8Array) {
    for (let i = 0; i < 16; i++) state[i] = Si[state[i]!]!;
  }

  /**
   * Cyclically shift each row of the state:
   * row 0: 0, row 1: 1 left, row 2: 2 left, row 3: 3 left.
   */
  private shiftRows(state: Uint8Array) {
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t!;
    t = state[2];
    const t2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t!;
    state[14] = t2!;
    t = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t!;
  }

  /** Inverse of shiftRows (right rotations by row index). */
  private invShiftRows(state: Uint8Array) {
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t!;
    t = state[2];
    const t2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t!;
    state[14] = t2!;
    t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t!;
  }

  /**
   * MixColumns: multiply each state column by the fixed matrix in GF(2^8):
   * [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]
   */
  private mixColumns(state: Uint8Array) {
    for (let c = 0; c < 16; c += 4) {
      const a0 = state[c]!,
        a1 = state[c + 1]!,
        a2 = state[c + 2]!,
        a3 = state[c + 3]!;
      state[c] = (gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3) & 0xff;
      state[c + 1] = (a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3) & 0xff;
      state[c + 2] = (a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3)) & 0xff;
      state[c + 3] = (gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2)) & 0xff;
    }
  }

  /** Inverse MixColumns using multipliers [14 11 13 9; ...] in GF(2^8). */
  private invMixColumns(state: Uint8Array) {
    for (let c = 0; c < 16; c += 4) {
      const a0 = state[c]!,
        a1 = state[c + 1]!,
        a2 = state[c + 2]!,
        a3 = state[c + 3]!;
      state[c] =
        (gfMul(a0, 14) ^ gfMul(a1, 11) ^ gfMul(a2, 13) ^ gfMul(a3, 9)) & 0xff;
      state[c + 1] =
        (gfMul(a0, 9) ^ gfMul(a1, 14) ^ gfMul(a2, 11) ^ gfMul(a3, 13)) & 0xff;
      state[c + 2] =
        (gfMul(a0, 13) ^ gfMul(a1, 9) ^ gfMul(a2, 14) ^ gfMul(a3, 11)) & 0xff;
      state[c + 3] =
        (gfMul(a0, 11) ^ gfMul(a1, 13) ^ gfMul(a2, 9) ^ gfMul(a3, 14)) & 0xff;
    }
  }

  // ---- BlockCipher interface ----

  /**
   * Encrypt one 16-byte block from inp[inOff..inOff+15] into out[outOff..].
   * Structure: AddRoundKey, (Nr-1) full rounds, final round (no MixColumns).
   */
  encryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    // Copy input block into working state (mutable).
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = inp[inOff + i]!;
    // Round 0 key addition.
    this.addRoundKey(s, 0);
    // Rounds 1..Nr-1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    for (let r = 1; r < this.Nr; r++) {
      this.subBytes(s);
      this.shiftRows(s);
      this.mixColumns(s);
      this.addRoundKey(s, r);
    }
    // Final round: no MixColumns.
    this.subBytes(s);
    this.shiftRows(s);
    this.addRoundKey(s, this.Nr);
    // Write result to output buffer.
    out.set(s, outOff);
  }

  /**
   * Decrypt one 16-byte block (inverse of encryptBlock).
   * Structure: AddRoundKey, (Nr-1) inverse rounds, final inverse round.
   */
  decryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    // Copy input block into working state.
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = inp[inOff + i]!;
    // Start with last round key.
    this.addRoundKey(s, this.Nr);
    // Rounds Nr-1..1: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
    for (let r = this.Nr - 1; r >= 1; r--) {
      this.invShiftRows(s);
      this.invSubBytes(s);
      this.addRoundKey(s, r);
      this.invMixColumns(s);
    }
    // Final inverse round: no InvMixColumns.
    this.invShiftRows(s);
    this.invSubBytes(s);
    this.addRoundKey(s, 0);
    // Write result.
    out.set(s, outOff);
  }
}

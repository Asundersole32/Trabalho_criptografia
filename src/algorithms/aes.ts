import type { BlockCipher } from "./utils/modes.ts";
import { S, Si, RCON } from "./utils/constants.ts";

// ---- AES math (tiny helpers) ----
function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>>= 1;
  }
  return p & 0xff;
}
const pack = (a: number, b: number, c: number, d: number) =>
  ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

// ---- Raw AES block cipher (no padding, no modes) ----
export class AESRaw implements BlockCipher {
  readonly blockSize = 16;

  private readonly Nr: number;
  private readonly roundKeys: Uint8Array[]; // 16 bytes each, Nr+1 total

  constructor(key: Uint8Array) {
    const len = key.length;
    if (len !== 16 && len !== 24 && len !== 32) {
      throw new Error("AES key must be 16/24/32 bytes");
    }
    const Nk = len / 4; // key words
    this.Nr = Nk + 6; // rounds
    this.roundKeys = this.expandKey(key, Nk, this.Nr);
  }

  private expandKey(key: Uint8Array, Nk: number, Nr: number): Uint8Array[] {
    const Nb = 4;
    const totalWords = Nb * (Nr + 1);
    const w = new Uint32Array(totalWords);

    // initial words
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

    // expansion
    for (let i = Nk, rconIdx = 0; i < totalWords; i++) {
      let temp = w[i - 1];
      if (i % Nk === 0) {
        temp = subWord(rotWord(temp)) ^ (RCON[rconIdx++] << 24);
      } else if (Nk > 6 && i % Nk === 4) {
        temp = subWord(temp);
      }
      w[i] = (w[i - Nk] ^ temp) >>> 0;
    }

    // words -> round-key blocks
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
  encryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = inp[inOff + i]!;
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
    out.set(s, outOff);
  }

  decryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = inp[inOff + i]!;
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
    out.set(s, outOff);
  }
}

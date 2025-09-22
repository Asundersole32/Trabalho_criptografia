// Keep your constants exactly as in your current file:
import {
  P as P0,
  S0 as S0c,
  S1 as S1c,
  S2 as S2c,
  S3 as S3c,
} from "./utils/constants.ts";
import type { BlockCipher } from "./utils/modes.ts";

const u32 = (n: number) => n >>> 0;
const xor32 = (a: number, b: number) => (a ^ b) >>> 0;
const add32 = (a: number, b: number) => ((a + b) | 0) >>> 0;

const pack4 = (b0: number, b1: number, b2: number, b3: number) =>
  u32((b0 << 24) | (b1 << 16) | (b2 << 8) | b3);
const unpack4 = (w: number) =>
  new Uint8Array([
    (w >>> 24) & 0xff,
    (w >>> 16) & 0xff,
    (w >>> 8) & 0xff,
    w & 0xff,
  ]);

export class BlowfishRaw implements BlockCipher {
  readonly blockSize = 8;
  private P: number[];
  private S: number[][]; // 4x256

  constructor(key: Uint8Array) {
    // Clone initial constants
    this.P = P0.slice();
    this.S = [S0c.slice(), S1c.slice(), S2c.slice(), S3c.slice()];

    // Key schedule (same as your original, minus padding/mode bits)
    let k = key;
    if (k.length < 72) {
      const ext = new Uint8Array(72);
      for (let i = 0; i < 72; i++) ext[i] = k[i % k.length];
      k = ext;
    }

    const pack4k = (i: number) => pack4(k[i], k[i + 1], k[i + 2], k[i + 3]);

    for (let i = 0, j = 0; i < 18; i++, j += 4) {
      const n = pack4k(j);
      this.P[i] = xor32(this.P[i], n);
    }
    let L = 0,
      R = 0;
    for (let i = 0; i < 18; i += 2) {
      [L, R] = this.encBlockWords(L, R);
      this.P[i] = L;
      this.P[i + 1] = R;
    }
    for (let s = 0; s < 4; s++) {
      for (let i = 0; i < 256; i += 2) {
        [L, R] = this.encBlockWords(L, R);
        this.S[s][i] = L;
        this.S[s][i + 1] = R;
      }
    }
  }

  private F = (x: number): number => {
    const a = (x >>> 24) & 0xff;
    const b = (x >>> 16) & 0xff;
    const c = (x >>> 8) & 0xff;
    const d = x & 0xff;
    let res = add32(this.S[0][a], this.S[1][b]);
    res = xor32(res, this.S[2][c]);
    return add32(res, this.S[3][d]);
  };

  private encBlockWords = (L: number, R: number): [number, number] => {
    for (let i = 0; i < 16; i++) {
      L = xor32(L, this.P[i]);
      R = xor32(R, this.F(L));
      [L, R] = [R, L];
    }
    [L, R] = [R, L];
    R = xor32(R, this.P[16]);
    L = xor32(L, this.P[17]);
    return [L, R];
  };

  private decBlockWords = (L: number, R: number): [number, number] => {
    for (let i = 17; i > 1; i--) {
      L = xor32(L, this.P[i]);
      R = xor32(R, this.F(L));
      [L, R] = [R, L];
    }
    [L, R] = [R, L];
    R = xor32(R, this.P[1]);
    L = xor32(L, this.P[0]);
    return [L, R];
  };

  encryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    const L = pack4(inp[inOff], inp[inOff + 1], inp[inOff + 2], inp[inOff + 3]);
    const R = pack4(
      inp[inOff + 4],
      inp[inOff + 5],
      inp[inOff + 6],
      inp[inOff + 7]
    );
    const [eL, eR] = this.encBlockWords(L, R);
    out.set(unpack4(eL), outOff);
    out.set(unpack4(eR), outOff + 4);
  }

  decryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    const L = pack4(inp[inOff], inp[inOff + 1], inp[inOff + 2], inp[inOff + 3]);
    const R = pack4(
      inp[inOff + 4],
      inp[inOff + 5],
      inp[inOff + 6],
      inp[inOff + 7]
    );
    const [dL, dR] = this.decBlockWords(L, R);
    out.set(unpack4(dL), outOff);
    out.set(unpack4(dR), outOff + 4);
  }
}

import {
  P as P0,
  S0 as S0c,
  S1 as S1c,
  S2 as S2c,
  S3 as S3c,
} from "./utils/constants.ts";
import { u32, xor32, add32, pack4, unpack4 } from "./utils/util.ts";
import type { BlockCipher } from "./utils/modes.ts";


/**
 * Minimal Blowfish block cipher core (8-byte block).
 *
 *  - Key schedule: XOR user key across P-array, then repeatedly encrypt 0x00000000/0x00000000
 *    to populate P and S boxes (per Blowfish spec).
 *  - 16-round Feistel network with F-function and P-array subkeys.
 *  - Big-endian packing for blocks.
 */
export class BlowfishRaw implements BlockCipher {
  /** Blowfish operates on 64-bit (8-byte) blocks. */
  readonly blockSize = 8;

  /** 18-entry P-array (subkeys). */
  private P: number[];

  /** Four 256-entry S-boxes. */
  private S: number[][]; // 4x256

  constructor(key: Uint8Array) {
    // Start from the standard initial constants (P0/S0..S3) — do not modify them in place.
    this.P = P0.slice();
    this.S = [S0c.slice(), S1c.slice(), S2c.slice(), S3c.slice()];

    // --- Key schedule ---
    // We need 18 words (72 bytes) to XOR across the P-array.
    // If the provided key is shorter, repeat its bytes until we have 72.
    let k = key;
    if (k.length < 72) {
      const ext = new Uint8Array(72);
      for (let i = 0; i < 72; i++) ext[i] = k[i % k.length];
      k = ext;
    }

    // Helper: read 4 bytes from k (big-endian) to form a 32-bit word.
    const pack4k = (i: number) => pack4(k[i], k[i + 1], k[i + 2], k[i + 3]);

    // 1) XOR the key material into the P-array.
    for (let i = 0, j = 0; i < 18; i++, j += 4) {
      const n = pack4k(j);
      this.P[i] = xor32(this.P[i], n);
    }

    // 2) Encrypt an all-zero block; replace P entries with the outputs.
    let L = 0,
      R = 0;
    for (let i = 0; i < 18; i += 2) {
      [L, R] = this.encBlockWords(L, R);
      this.P[i] = L;
      this.P[i + 1] = R;
    }

    // 3) Continue encrypting; replace each S-box entry pair with outputs.
    for (let s = 0; s < 4; s++) {
      for (let i = 0; i < 256; i += 2) {
        [L, R] = this.encBlockWords(L, R);
        this.S[s][i] = L;
        this.S[s][i + 1] = R;
      }
    }
  }

  /**
   * Blowfish F-function.
   * Splits x into four bytes a,b,c,d and combines S-box lookups:
   *   F(x) = ((S0[a] + S1[b]) XOR S2[c]) + S3[d]   (all 32-bit)
   */
  private F = (x: number): number => {
    const a = (x >>> 24) & 0xff;
    const b = (x >>> 16) & 0xff;
    const c = (x >>> 8) & 0xff;
    const d = x & 0xff;
    let res = add32(this.S[0][a], this.S[1][b]);
    res = xor32(res, this.S[2][c]);
    return add32(res, this.S[3][d]);
  };

  /**
   * Encrypt a single 64-bit block given as two 32-bit words (L,R).
   * Implements 16 Feistel rounds:
   *   for i=0..15:
   *     L = L XOR P[i]
   *     R = R XOR F(L)
   *     swap(L,R)
   * After rounds, swap once more, then:
   *   R = R XOR P[16]
   *   L = L XOR P[17]
   */
  private encBlockWords = (L: number, R: number): [number, number] => {
    for (let i = 0; i < 16; i++) {
      L = xor32(L, this.P[i]);
      R = xor32(R, this.F(L));
      [L, R] = [R, L]; // Feistel swap
    }
    [L, R] = [R, L]; // undo last swap
    R = xor32(R, this.P[16]);
    L = xor32(L, this.P[17]);
    return [L, R];
  };

  /**
   * Decrypt a single 64-bit block given as two 32-bit words (L,R).
   * Same structure as enc but P-array is applied in reverse:
   *   for i=17..2:
   *     L = L XOR P[i]
   *     R = R XOR F(L)
   *     swap(L,R)
   * After rounds, swap once more, then:
   *   R = R XOR P[1]
   *   L = L XOR P[0]
   */
  private decBlockWords = (L: number, R: number): [number, number] => {
    for (let i = 17; i > 1; i--) {
      L = xor32(L, this.P[i]);
      R = xor32(R, this.F(L));
      [L, R] = [R, L]; // Feistel swap
    }
    [L, R] = [R, L]; // undo last swap
    R = xor32(R, this.P[1]);
    L = xor32(L, this.P[0]);
    return [L, R];
  };

  /**
   * Encrypt one 8-byte block.
   *
   * Parameters:
   *  - `inp`:  source bytes
   *  - `inOff`: byte offset into `inp` where the 8-byte block starts
   *  - `out`: destination buffer
   *  - `outOff`: byte offset into `out` where to write the 8-byte ciphertext
   *
   * Steps:
   *  1) Read 8 bytes from `inp` at `inOff` and split into two 32-bit big-endian words (L,R).
   *  2) Run the 16-round Blowfish core (`encBlockWords`) to get (eL,eR).
   *  3) Write (eL,eR) back to `out` at `outOff` as 8 bytes, big-endian.
   *
   * Notes:
   *  - This method assumes `inp`/`out` have enough space; no bounds checks are performed.
   *  - Endianness is big-endian, as per the Blowfish spec.
   */
  encryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    // Load 64 bits as two 32-bit big-endian words.
    const L = pack4(inp[inOff], inp[inOff + 1], inp[inOff + 2], inp[inOff + 3]);
    const R = pack4(
      inp[inOff + 4],
      inp[inOff + 5],
      inp[inOff + 6],
      inp[inOff + 7]
    );

    // Core 16-round Feistel encryption on the two 32-bit halves.
    const [eL, eR] = this.encBlockWords(L, R);

    // Store the encrypted words back as 8 bytes (big-endian).
    out.set(unpack4(eL), outOff);
    out.set(unpack4(eR), outOff + 4);
  }

  /**
   * Decrypt one 8-byte block.
   *
   * Parameters:
   *  - `inp`:  source bytes
   *  - `inOff`: byte offset into `inp` where the 8-byte block starts
   *  - `out`: destination buffer
   *  - `outOff`: byte offset into `out` where to write the 8-byte plaintext
   *
   * Steps:
   *  1) Read 8 bytes from `inp` at `inOff` and split into two 32-bit big-endian words (L,R).
   *  2) Run the reverse 16-round Feistel (`decBlockWords`) to get (dL,dR).
   *  3) Write (dL,dR) back to `out` at `outOff` as 8 bytes, big-endian.
   *
   * Notes:
   *  - Like `encryptBlock`, this performs no bounds checks.
   *  - Must be used with the *same* key schedule as used to encrypt.
   */
  decryptBlock(
    inp: Uint8Array,
    inOff: number,
    out: Uint8Array,
    outOff: number
  ): void {
    // Load 64 bits as two 32-bit big-endian words.
    const L = pack4(inp[inOff], inp[inOff + 1], inp[inOff + 2], inp[inOff + 3]);
    const R = pack4(
      inp[inOff + 4],
      inp[inOff + 5],
      inp[inOff + 6],
      inp[inOff + 7]
    );

    // Core 16-round Feistel *decryption* on the two 32-bit halves.
    const [dL, dR] = this.decBlockWords(L, R);

    // Store the decrypted words back as 8 bytes (big-endian).
    out.set(unpack4(dL), outOff);
    out.set(unpack4(dR), outOff + 4);
  }
}

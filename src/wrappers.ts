import { BlowfishRaw } from "./algorithms/blowfish.ts";
import { TwofishRaw } from "./algorithms/twofish.ts";
import { AESRaw } from "./algorithms/aes.ts";

import {
  toBytes,
  toString,
  Bytes,
  Input,
  Mode,
} from "./algorithms/utils/util.ts";
import { pkcs7Pad, pkcs7Unpad } from "./algorithms/utils/padding.ts";
import {
  BlockCipher,
  runModeRaw,
  cfbEncryptRaw,
  cfbDecryptRaw,
  ofbXorRaw,
  ctrXorRaw,
} from "./algorithms/utils/modes.ts";

type PaddingKind = "PKCS7" | "None";

interface FriendlyOpts {
  mode?: Mode; // default 'CBC'
  iv?: Bytes; // required for 'CBC'
  padding?: PaddingKind; // default 'PKCS7'
}

abstract class FriendlyCipher {
  protected readonly raw: BlockCipher;
  protected readonly mode: Mode;
  protected readonly iv?: Bytes;
  protected readonly padding: PaddingKind;

  constructor(
    raw: BlockCipher,
    { mode = "CBC", iv, padding = "PKCS7" }: FriendlyOpts
  ) {
    this.raw = raw;
    this.mode = mode;
    this.iv = iv;
    this.padding = padding;
    if (this.mode === "CBC" && (!iv || iv.length !== raw.blockSize)) {
      throw new Error(`CBC mode requires IV of ${raw.blockSize} bytes`);
    }
  }

  encrypt(plain: Input): Uint8Array {
    const p = toBytes(plain);
    const input =
      this.padding === "PKCS7" ? pkcs7Pad(p, this.raw.blockSize) : p;
    return runModeRaw(this.raw, this.mode, input, this.iv, true);
  }

  decrypt(cipher: Bytes): Uint8Array {
    const out = runModeRaw(this.raw, this.mode, cipher, this.iv, false);
    return this.padding === "PKCS7" ? pkcs7Unpad(out, this.raw.blockSize) : out;
  }

  decryptToString(cipher: Bytes): string {
    return toString(this.decrypt(cipher));
  }
}

/** Friendly Blowfish (padding + mode + IV handled) */
export class BlowfishCipher extends FriendlyCipher {
  constructor(key: Input, opts: FriendlyOpts = {}) {
    super(new BlowfishRaw(toBytes(key)), opts);
  }
}

/** Friendly Twofish (padding + mode + IV handled) */
export class TwofishCipher extends FriendlyCipher {
  constructor(key: Input, opts: FriendlyOpts = {}) {
    super(new TwofishRaw(toBytes(key)), opts);
  }
}

// Extend supported modes for AES
export type AesMode = "ECB" | "CBC" | "CFB" | "OFB" | "CTR";

export interface AesOpts {
  mode?: AesMode; // default 'CBC'
  iv?: Bytes; // required for CBC/CFB/OFB
  counter?: Bytes; // required for CTR (if used)
  segmentSize?: number; // CFB only; bytes 1..blockSize (defaults to blockSize)
  padding?: PaddingKind; // applies to block modes only (ECB/CBC)
}

export class AESCipher {
  private readonly raw: BlockCipher;
  private readonly mode: AesMode;
  private readonly iv?: Bytes;
  private readonly counter?: Bytes;
  private readonly segmentSize?: number;
  private readonly padding: PaddingKind;

  constructor(key: Input, opts: AesOpts = {}) {
    this.raw = new AESRaw(toBytes(key));
    this.mode = opts.mode ?? "CBC";
    this.iv = opts.iv;
    this.counter = opts.counter;
    this.segmentSize = opts.segmentSize;
    this.padding = opts.padding ?? "PKCS7";

    const bs = this.raw.blockSize;
    if (this.mode === "CBC" || this.mode === "CFB" || this.mode === "OFB") {
      if (!this.iv || this.iv.length !== bs)
        throw new Error(`${this.mode} requires IV of ${bs} bytes`);
    }
    if (this.mode === "CTR") {
      if (!this.counter || this.counter.length !== bs)
        throw new Error(`CTR requires counter of ${bs} bytes`);
    }
  }

  encrypt(plain: Input): Uint8Array {
    const bs = this.raw.blockSize;
    const p = toBytes(plain);

    if (this.mode === "ECB" || this.mode === "CBC") {
      const input = this.padding === "PKCS7" ? pkcs7Pad(p, bs) : p;
      return runModeRaw(this.raw, this.mode, input, this.iv, true);
    }
    if (this.mode === "CFB") {
      return cfbEncryptRaw(this.raw, p, this.iv!, this.segmentSize ?? bs);
    }
    if (this.mode === "OFB") return ofbXorRaw(this.raw, p, this.iv!);
    // CTR
    return ctrXorRaw(this.raw, p, this.counter!);
  }

  decrypt(cipher: Bytes): Uint8Array {
    const bs = this.raw.blockSize;

    if (this.mode === "ECB" || this.mode === "CBC") {
      const out = runModeRaw(this.raw, this.mode, cipher, this.iv, false);
      return this.padding === "PKCS7" ? pkcs7Unpad(out, bs) : out;
    }
    if (this.mode === "CFB") {
      return cfbDecryptRaw(this.raw, cipher, this.iv!, this.segmentSize ?? bs);
    }
    if (this.mode === "OFB") return ofbXorRaw(this.raw, cipher, this.iv!);
    // CTR
    return ctrXorRaw(this.raw, cipher, this.counter!);
  }

  decryptToString(cipher: Bytes): string {
    return toString(this.decrypt(cipher));
  }
}

/** Also export the raw API for fair benchmarking */
export { BlowfishRaw } from "./algorithms/blowfish.ts";
export { TwofishRaw } from "./algorithms/twofish.ts";
export { AESRaw } from "./algorithms/aes.ts";
export * as Modes from "./algorithms/utils/modes.ts";
export * as Padding from "./algorithms/utils/padding.ts";

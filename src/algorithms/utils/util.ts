import { isUint8Array } from "util/types";

export type Bytes = Uint8Array;
export type Input = string | Uint8Array;
export type Mode = "ECB" | "CBC";
export type StreamMode = "CFB" | "OFB" | "CTR";
export type AnyMode = Mode | StreamMode;

export const toBytes = (v: Input): Uint8Array =>
  typeof v === "string" ? new TextEncoder().encode(v) : v;

export function asBytes(x: unknown): Uint8Array {
  if (x instanceof Uint8Array) return x;
  if (Buffer.isBuffer(x)) return new Uint8Array(x);
  if (typeof x === "string") return new Uint8Array(Buffer.from(x, "base64")); // assume base64
  throw new Error("Expected bytes or base64 string");
}

export const toString = (u8: Uint8Array): string =>
  new TextDecoder().decode(u8);

export function assertMultipleOf(
  n: number,
  blockSize: number,
  label = "data"
): void {
  if (n % blockSize !== 0)
    throw new Error(`${label} length must be a multiple of ${blockSize} bytes`);
}

// Optional hex helpers for convenience
export const hex = {
  toBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error("hex must have even length");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      const v = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
      if ((v as any) !== v || Number.isNaN(v)) throw new Error("invalid hex");
      out[i] = v;
    }
    return out;
  },
  fromBytes(bytes: Bytes): string {
    let s = "";
    for (let i = 0; i < bytes.length; i++)
      s += bytes[i]!.toString(16).padStart(2, "0");
    return s;
  },
};

export function normalizeKey(key: any): Uint8Array {
  if (isUint8Array(key)) return key;
  if (ArrayBuffer.isView(key))
    return new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
  if (key instanceof ArrayBuffer) return new Uint8Array(key);

  if (typeof key === "string") {
    const s = key.trim();
    // try base64 first (length multiple of 4 and valid alphabet)
    if (s.length % 4 === 0 && /^[A-Za-z0-9+/=]+$/.test(s)) {
      try {
        const k = new Uint8Array(Buffer.from(s, "base64"));
        if (k.length === 16 || 24 || 32) return k;
      } catch {}
    }
    // try hex
    if (/^[0-9a-fA-F]+$/.test(s)) {
      const k = hex.toBytes(s);
      if (k.length === 16 || k.length === 24 || k.length === 32) return k;
    }
    // fall back to UTF-8 (rarely what you want for keys)
    return new TextEncoder().encode(s);
  }
  throw new Error("Unsupported key type");
}

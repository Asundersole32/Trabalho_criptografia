export type Bytes = Uint8Array;
export type Input = string | Uint8Array;
export type Mode = "ECB" | "CBC";
export type StreamMode = "CFB" | "OFB" | "CTR";
export type AnyMode = Mode | StreamMode;

export const toBytes = (v: Input): Uint8Array =>
  typeof v === "string" ? new TextEncoder().encode(v) : v;

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

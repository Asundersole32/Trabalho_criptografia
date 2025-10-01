// perf.ts
// RAW-mode performance harness for AES, Twofish, and Blowfish (manual implementations).
// ECB/CBC, NO padding (inputs block-aligned). Adaptive, multi-sampled measurements.
//
// Run examples:
//   npx ts-node perf.ts
//   node --expose-gc -r ts-node/register perf.ts

import * as os from "node:os";
import { PerformanceObserver } from "node:perf_hooks";

// ---- raw block ciphers -----------------------------------------------------
import { AESRaw } from "./algorithms/aes.ts";
import { TwofishRaw } from "./algorithms/twofish.ts";
import { BlowfishRaw } from "./algorithms/blowfish.ts";

// ---- generic RAW modes (block-size agnostic) -------------------------------
import {
  ecbEncryptRaw,
  ecbDecryptRaw,
  cbcEncryptRaw,
  cbcDecryptRaw,
  ecbEncryptInplaceRaw,
  ecbDecryptInplaceRaw,
  cbcEncryptInplaceRaw,
  cbcDecryptInplaceRaw,
  type BlockCipher,
} from "./algorithms/utils/modes.ts";

// ---- measurement + utils ---------------------------------------------------

type Algo = "AES" | "Twofish" | "Blowfish";
type Mode = "ECB" | "CBC";
type Op = "encrypt" | "decrypt";

type Sample = {
  iters: number;
  // native units (after blank subtraction)
  wallNs: number;            // hrtime bigint in nanoseconds
  cpuUserMicros: number;     // process.cpuUsage user µs
  cpuSysMicros: number;      // process.cpuUsage sys µs
  gcMillis: number;          // total GC ms during the sample
};

type Summary = {
  algo: Algo;
  mode: Mode;
  sizeLabel: string;
  sizeBytes: number;
  op: Op;
  samplesKept: number;

  // throughput / normalized
  nsPerByte_median: number;
  nsPerByte_p10: number;
  nsPerByte_p90: number;
  MiBps_median: number;
  cpuPct_median: number;

  // absolute times (native units; medians)
  wallNs_median: number;
  cpuUserMicros_median: number;
  cpuSysMicros_median: number;

  // iteration visibility
  iters_median: number;

  // diagnostics
  gcMillis_median: number;
  rssPeakKiB: number; // lifetime high-water for the process
};

// configuration
const TARGET_NS = 300_000_000n; // ~300 ms per sample (nanoseconds)
const SAMPLES = 9;              // total samples per case
const DROP_FIRST = 1;           // drop first warm sample
const MiB = 1024 * 1024;

// deterministic PRNG (no Node 'crypto')
function makePRNG(seed = 0x12345678) {
  let x = seed | 0;
  return (len: number): Uint8Array => {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      x ^= x << 13;
      x ^= x >>> 17;
      x ^= x << 5;
      out[i] = x & 0xff;
    }
    return out;
  };
}

function maybeGC() {
  const g = (global as any).gc as (() => void) | undefined;
  if (g) g();
}

// GC observer
let gcMillisAccum = 0;
const obs = new PerformanceObserver((list) => {
  for (const e of list.getEntries()) {
    // e.duration is in milliseconds
    // @ts-ignore
    if (e.entryType === "gc") gcMillisAccum += e.duration;
  }
});
obs.observe({ entryTypes: ["gc"], buffered: false });

// quantiles
function quantile(xs: number[], q: number): number {
  if (xs.length === 0) return NaN;
  const a = xs.slice().sort((u, v) => u - v);
  const idx = (a.length - 1) * q;
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return a[lo]!;
  const w = idx - lo;
  return a[lo]! * (1 - w) + a[hi]! * w;
}
const median = (xs: number[]) => quantile(xs, 0.5);

// measure a loop body run for a fixed number of iterations
function timeOnce(iters: number, body: () => void): Sample {
  maybeGC();
  gcMillisAccum = 0;

  const cpu0 = process.cpuUsage();
  const t0 = process.hrtime.bigint();

  for (let i = 0; i < iters; i++) body();

  const t1 = process.hrtime.bigint();
  const cpu = process.cpuUsage(cpu0);

  return {
    iters,
    wallNs: Number(t1 - t0),       // keep native ns (Number is safe here)
    cpuUserMicros: cpu.user,       // µs
    cpuSysMicros: cpu.system,      // µs
    gcMillis: gcMillisAccum,       // ms
  };
}

// ramp iteration count until TARGET_NS is reached, then measure exactly that pass
function runTimedToTarget(body: () => void): Sample {
  let iters = 1;
  while (true) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < iters; i++) body();
    const dt = process.hrtime.bigint() - t0;
    if (dt >= TARGET_NS) break;
    iters *= 2;
  }
  return timeOnce(iters, body);
}

// perform a work measurement and a matching blank-loop measurement, then subtract
function measureWithBlank(work: () => void, blank: () => void): Sample {
  const sWork = runTimedToTarget(work);
  const sBlank = timeOnce(sWork.iters, blank);

  // subtract (saturate at 0 to avoid tiny negative jitter)
  const wallNs = Math.max(0, sWork.wallNs - sBlank.wallNs);
  const cpuUserMicros = Math.max(0, sWork.cpuUserMicros - sBlank.cpuUserMicros);
  const cpuSysMicros = Math.max(0, sWork.cpuSysMicros - sBlank.cpuSysMicros);
  const gcMillis = Math.max(0, sWork.gcMillis - sBlank.gcMillis);

  return {
    iters: sWork.iters,
    wallNs,
    cpuUserMicros,
    cpuSysMicros,
    gcMillis,
  };
}

// ---- core benchmark --------------------------------------------------------

async function main() {
  // environment header
  const cpuInfo = os.cpus()?.[0];
  console.log(`Node: ${process.version}`);
  console.log(`V8: ${process.versions.v8}`);
  console.log(`Platform: ${process.platform} ${process.arch}`);
  if (cpuInfo) console.log(`CPU: ${cpuInfo.model} @ ${cpuInfo.speed}MHz`);
  if (process.execArgv.length) console.log(`execArgv: ${process.execArgv.join(" ")}`);
  console.log(`PID: ${process.pid}`);
  console.log(`(RAW modes only; no padding; timings exclude key schedule.)\n`);

  const prng = makePRNG(0xc0ffee);

  // keys: AES/Twofish use 16B (128-bit); Blowfish arbitrary
  const key16 = prng(16);
  const keyBF = prng(16);

  // IVs per block size
  const iv16 = prng(16);
  const iv8 = prng(8);

  // message sizes
  const sizes = [
    { label: "16B", bytes: 16 },
    { label: "4KiB", bytes: 4 * 1024 },
    { label: "1MiB", bytes: 1 * 1024 * 1024 },
  ] as const;

  // JIT warmup (small deterministic loops; out-of-place helpers OK here)
  {
    const warm = prng(16 * 16); // 256B
    const aes = new AESRaw(key16);
    const tf = new TwofishRaw(key16);
    const bf = new BlowfishRaw(keyBF);

    for (let i = 0; i < 50; i++) {
      const ctAE = ecbEncryptRaw(aes, warm);
      const ptAE = ecbDecryptRaw(aes, ctAE);
      const ctAC = cbcEncryptRaw(aes, warm, iv16);
      const ptAC = cbcDecryptRaw(aes, ctAC, iv16);
      if (ptAE.length !== warm.length || ptAC.length !== warm.length) throw new Error("AES warmup mismatch");

      const ctTE = ecbEncryptRaw(tf, warm);
      const ptTE = ecbDecryptRaw(tf, ctTE);
      const ctTC = cbcEncryptRaw(tf, warm, iv16);
      const ptTC = cbcDecryptRaw(tf, ctTC, iv16);
      if (ptTE.length !== warm.length || ptTC.length !== warm.length) throw new Error("TF warmup mismatch");

      const ctBE = ecbEncryptRaw(bf, warm);
      const ptBE = ecbDecryptRaw(bf, ctBE);
      const ctBC = cbcEncryptRaw(bf, warm, iv8);
      const ptBC = cbcDecryptRaw(bf, ctBC, iv8);
      if (ptBE.length !== warm.length || ptBC.length !== warm.length) throw new Error("BF warmup mismatch");
    }
  }

  const summaries: Summary[] = [];
  const modes: Mode[] = ["ECB", "CBC"];

  for (const { label, bytes } of sizes) {
    const plain = prng(bytes);

    // cipher instances (exclude key schedule from timed loops)
    const aes = new AESRaw(key16);
    const tf = new TwofishRaw(key16);
    const bf = new BlowfishRaw(keyBF);

    // precompute ciphertext samples for decrypt (outside timing)
    const pre: Record<Algo, Record<Mode, Uint8Array>> = {
      AES: { ECB: ecbEncryptRaw(aes, plain), CBC: cbcEncryptRaw(aes, plain, iv16) },
      Twofish: { ECB: ecbEncryptRaw(tf, plain), CBC: cbcEncryptRaw(tf, plain, iv16) },
      Blowfish: { ECB: ecbEncryptRaw(bf, plain), CBC: cbcEncryptRaw(bf, plain, iv8) },
    };

    // correctness checks (once per algo/mode/size)
    {
      const aesECB = ecbDecryptRaw(aes, pre.AES.ECB);
      const aesCBC = cbcDecryptRaw(aes, pre.AES.CBC, iv16);
      if (!equal(aesECB, plain) || !equal(aesCBC, plain)) throw new Error("AES correctness failed");
      const tfECB = ecbDecryptRaw(tf, pre.Twofish.ECB);
      const tfCBC = cbcDecryptRaw(tf, pre.Twofish.CBC, iv16);
      if (!equal(tfECB, plain) || !equal(tfCBC, plain)) throw new Error("Twofish correctness failed");
      const bfECB = ecbDecryptRaw(bf, pre.Blowfish.ECB);
      const bfCBC = cbcDecryptRaw(bf, pre.Blowfish.CBC, iv8);
      if (!equal(bfECB, plain) || !equal(bfCBC, plain)) throw new Error("Blowfish correctness failed");
    }

    for (const mode of modes) {
      for (const [algo, impl] of [
        ["AES", { cipher: aes as BlockCipher, iv: iv16 }],
        ["Twofish", { cipher: tf as BlockCipher, iv: iv16 }],
        ["Blowfish", { cipher: bf as BlockCipher, iv: iv8 }],
      ] as const) {
        for (const op of ["encrypt", "decrypt"] as const) {
          // Preallocate reusable out buffer
          const out = new Uint8Array(bytes);

          // Work function (writes into `out`) and blank function (loop overhead mimic)
          const work = (() => {
            const c = impl.cipher;
            const iv = impl.iv;
            const sample = pre[algo as Algo][mode];
            let checksum = 0 >>> 0;

            if (op === "encrypt") {
              if (mode === "ECB") {
                return () => {
                  ecbEncryptInplaceRaw(c, plain, out);
                  checksum ^= out[0]! ^ out[out.length - 1]!;
                  if (checksum === 0xdeadbeef) (globalThis as any).__sink = checksum;
                };
              } else {
                return () => {
                  cbcEncryptInplaceRaw(c, plain, iv, out);
                  checksum ^= out[0]! ^ out[out.length - 1]!;
                  if (checksum === 0xdeadbeef) (globalThis as any).__sink = checksum;
                };
              }
            } else {
              if (mode === "ECB") {
                return () => {
                  ecbDecryptInplaceRaw(c, sample, out);
                  checksum ^= out[0]! ^ out[out.length - 1]!;
                  if (checksum === 0xdeadbeef) (globalThis as any).__sink = checksum;
                };
              } else {
                return () => {
                  cbcDecryptInplaceRaw(c, sample, iv, out);
                  checksum ^= out[0]! ^ out[out.length - 1]!;
                  if (checksum === 0xdeadbeef) (globalThis as any).__sink = checksum;
                };
              }
            }
          })();

          // blank that mimics the per-iteration shape without crypto
          const tap = plain; // stable bytes to touch
          const blank = () => {
            let s = 0;
            s ^= tap[0]! ^ tap[tap.length - 1]!;
            if (s === 257) (globalThis as any).__sink2 = s;
          };

          // collect samples
          const samples: Sample[] = [];
          for (let k = 0; k < SAMPLES; k++) {
            samples.push(measureWithBlank(work, blank));
          }
          const kept = samples.slice(DROP_FIRST);

          // per-sample derived metrics
          const nsPerByte = kept.map((s) => s.wallNs / (s.iters * bytes));
          const MiBps = kept.map((s) => {
            const processed = s.iters * bytes; // bytes
            const seconds = s.wallNs / 1e9;    // convert ns -> s for throughput only
            return (processed / MiB) / seconds;
          });
          const cpuPct = kept.map((s) => {
            const cpuMicros = s.cpuUserMicros + s.cpuSysMicros; // µs
            const wallMicros = s.wallNs / 1e3;                   // ns -> µs
            return (cpuMicros / wallMicros) * 100;
          });

          // summarize
          const sum: Summary = {
            algo: algo as Algo,
            mode,
            sizeLabel: label,
            sizeBytes: bytes,
            op,
            samplesKept: kept.length,

            nsPerByte_median: median(nsPerByte),
            nsPerByte_p10: quantile(nsPerByte, 0.10),
            nsPerByte_p90: quantile(nsPerByte, 0.90),
            MiBps_median: median(MiBps),
            cpuPct_median: median(cpuPct),

            wallNs_median: median(kept.map((s) => s.wallNs)),
            cpuUserMicros_median: median(kept.map((s) => s.cpuUserMicros)),
            cpuSysMicros_median: median(kept.map((s) => s.cpuSysMicros)),
            iters_median: median(kept.map((s) => s.iters)),

            gcMillis_median: median(kept.map((s) => s.gcMillis)),
            rssPeakKiB: process.resourceUsage().maxRSS, // lifetime peak KiB
          };
          summaries.push(sum);
        }
      }
    }
  }

  // ---- Report --------------------------------------------------------------

  const rows = summaries.map((r) => ({
    algo: r.algo,
    mode: r.mode,
    op: r.op.toUpperCase(),
    size: r.sizeLabel,
    samples: r.samplesKept,

    // absolute times (native units; medians)
    "wall ns (p50)": Math.trunc(r.wallNs_median),
    "cpu usr µs (p50)": Math.trunc(r.cpuUserMicros_median),
    "cpu sys µs (p50)": Math.trunc(r.cpuSysMicros_median),

    // throughput / normalized
    "ns/byte (p50)": round(r.nsPerByte_median, 3),
    "ns/byte (p10–p90)": `${round(r.nsPerByte_p10, 3)}–${round(r.nsPerByte_p90, 3)}`,
    "MiB/s (p50)": round(r.MiBps_median, 2),
    "CPU% (p50)": round(r.cpuPct_median, 1),

    // iteration visibility
    "iters (p50)": Math.trunc(r.iters_median),

    // GC + RSS
    "GC ms (p50)": round(r.gcMillis_median, 3),
    "maxRSS (KiB)": r.rssPeakKiB,
  }));

  console.log("\nAdaptive time-boxed results (native units; medians):");
  console.table(rows);
}

function round(n: number, d = 2) {
  return Number.isFinite(n) ? Number(n.toFixed(d)) : n;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

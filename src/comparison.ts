// perf.ts
// RAW-mode performance harness for AES, Twofish, and Blowfish (manual implementations).
// Compares ECB and CBC with NO padding (inputs are block-aligned).
// Uses only raw BlockCipher cores + raw mode helpers; no friendly wrappers, no PKCS#7/5.
//
// Run examples:
//   npx ts-node perf.ts
//   # (recommended for steadier memory readings):
//   node --expose-gc -r ts-node/register perf.ts
//
// Note: "rss peak (MB)" uses process.resourceUsage().maxRSS (lifetime peak for the process).

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
  type BlockCipher,
} from "./algorithms/utils/modes.ts";

// ---- measurement + utils ---------------------------------------------------

type Algo = "AES" | "Twofish" | "Blowfish";
type Mode = "ECB" | "CBC";

type Metrics = {
  algo: Algo;
  mode: Mode;
  label: string;
  op: "encrypt" | "decrypt";
  runs: number;
  sizeBytes: number;
  wallMs: number;
  cpuUserMs: number;
  cpuSysMs: number;
  rssDeltaMB: number;
  heapDeltaMB: number;
  rssPeakMB: number; // <— new: lifetime peak RSS for the process (MiB)
  checksum: number; // anti-DCE sanity
};

const MB = (n: number) => n / (1024 * 1024);          // bytes -> MiB
const MB_FROM_KiB = (kb: number) => kb / 1024;         // KiB -> MiB
const format = (n: number, decimals = 3) =>
  Number.isFinite(n) ? Number(n.toFixed(decimals)) : n;

function maybeGC() {
  const g = (global as any).gc as (() => void) | undefined;
  if (g) g();
}

function measure(fn: () => void) {
  maybeGC();
  const mem0 = process.memoryUsage();
  const cpu0 = process.cpuUsage();
  const ru0 = process.resourceUsage(); // includes maxRSS (in KiB)
  const t0 = process.hrtime.bigint();

  fn();

  const t1 = process.hrtime.bigint();
  const cpu = process.cpuUsage(cpu0);
  const mem1 = process.memoryUsage();
  const ru1 = process.resourceUsage();

  return {
    wallMs: Number(t1 - t0) / 1e6,
    cpuUserMs: cpu.user / 1000,
    cpuSysMs: cpu.system / 1000,
    rssDeltaMB: MB(mem1.rss - mem0.rss),
    heapDeltaMB: MB(mem1.heapUsed - mem0.heapUsed),
    rssPeakMB: MB_FROM_KiB(ru1.maxRSS), // absolute lifetime peak for this process
  };
}

// ---- deterministic data (no Node 'crypto') ---------------------------------

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

// ---- benchmark core --------------------------------------------------------

async function main() {
  const prng = makePRNG(0xc0ffee);

  // keys: AES/Twofish use 16B (128-bit); Blowfish accepts arbitrary and does its schedule internally
  const key16 = prng(16);
  const keyBF = prng(16); // same length for fairness

  // IVs for CBC (per-block-size)
  const iv16 = prng(16);
  const iv8 = prng(8);

  // Three message sizes (all multiples of 16, hence also multiples of 8)
  const sizes = [
    { label: "16B", bytes: 16 },
    { label: "4KiB", bytes: 4 * 1024 },
    { label: "1MiB", bytes: 1 * 1024 * 1024 },
  ];

  // Run counts
  const runsArr = [1, 10, 100];
  const maxRuns = Math.max(...runsArr);

  // Warmup JIT with small raw loops (outside measurement)
  {
    const warm = prng(16 * 16); // 256B
    // AES
    {
      const aes = new AESRaw(key16);
      for (let i = 0; i < 50; i++) {
        const ctE = ecbEncryptRaw(aes, warm);
        const ptE = ecbDecryptRaw(aes, ctE);
        const ctC = cbcEncryptRaw(aes, warm, iv16);
        const ptC = cbcDecryptRaw(aes, ctC, iv16);
        if (ptE.length !== warm.length || ptC.length !== warm.length)
          throw new Error("AES warmup mismatch");
      }
    }
    // Twofish
    {
      const tf = new TwofishRaw(key16);
      for (let i = 0; i < 50; i++) {
        const ctE = ecbEncryptRaw(tf, warm);
        const ptE = ecbDecryptRaw(tf, ctE);
        const ctC = cbcEncryptRaw(tf, warm, iv16);
        const ptC = cbcDecryptRaw(tf, ctC, iv16);
        if (ptE.length !== warm.length || ptC.length !== warm.length)
          throw new Error("TF warmup mismatch");
      }
    }
    // Blowfish (8-byte blocks) — warm buffer is multiple of 16, OK
    {
      const bf = new BlowfishRaw(keyBF);
      for (let i = 0; i < 50; i++) {
        const ctE = ecbEncryptRaw(bf, warm);
        const ptE = ecbDecryptRaw(bf, ctE);
        const ctC = cbcEncryptRaw(bf, warm, iv8);
        const ptC = cbcDecryptRaw(bf, ctC, iv8);
        if (ptE.length !== warm.length || ptC.length !== warm.length)
          throw new Error("BF warmup mismatch");
      }
    }
  }

  const rows: Metrics[] = [];
  const modes: Mode[] = ["ECB", "CBC"] as const;

  for (const { label, bytes } of sizes) {
    const plain = prng(bytes);

    // Build cipher instances ONCE (exclude key schedule from timed loops)
    const aes = new AESRaw(key16);
    const tf = new TwofishRaw(key16);
    const bf = new BlowfishRaw(keyBF);

    // Precompute ciphertext samples for decrypt loops (outside timing)
    const pre: Record<Algo, Record<Mode, Uint8Array>> = {
      AES: {
        ECB: ecbEncryptRaw(aes, plain),
        CBC: cbcEncryptRaw(aes, plain, iv16),
      },
      Twofish: {
        ECB: ecbEncryptRaw(tf, plain),
        CBC: cbcEncryptRaw(tf, plain, iv16),
      },
      Blowfish: {
        ECB: ecbEncryptRaw(bf, plain),
        CBC: cbcEncryptRaw(bf, plain, iv8),
      },
    };

    // Quick correctness checks (once per algo/mode/size)
    {
      const aesECB = ecbDecryptRaw(aes, pre.AES.ECB);
      const aesCBC = cbcDecryptRaw(aes, pre.AES.CBC, iv16);
      if (!equal(aesECB, plain) || !equal(aesCBC, plain))
        throw new Error("AES correctness failed");

      const tfECB = ecbDecryptRaw(tf, pre.Twofish.ECB);
      const tfCBC = cbcDecryptRaw(tf, pre.Twofish.CBC, iv16);
      if (!equal(tfECB, plain) || !equal(tfCBC, plain))
        throw new Error("Twofish correctness failed");

      const bfECB = ecbDecryptRaw(bf, pre.Blowfish.ECB);
      const bfCBC = cbcDecryptRaw(bf, pre.Blowfish.CBC, iv8);
      if (!equal(bfECB, plain) || !equal(bfCBC, plain))
        throw new Error("Blowfish correctness failed");
    }

    for (const runs of runsArr) {
      for (const mode of modes) {
        // Selectors for IV/cipher
        const bench = {
          AES: { cipher: aes as BlockCipher, iv: iv16 },
          Twofish: { cipher: tf as BlockCipher, iv: iv16 },
          Blowfish: { cipher: bf as BlockCipher, iv: iv8 },
        } as const;

        // ========== ENCRYPT ==========
        for (const algo of ["AES", "Twofish", "Blowfish"] as const) {
          let checksum = 0;
          const { cipher, iv } = bench[algo];

          const enc = measure(() => {
            for (let i = 0; i < runs; i++) {
              const ct =
                mode === "ECB"
                  ? ecbEncryptRaw(cipher, plain)
                  : cbcEncryptRaw(cipher, plain, iv);
              checksum ^= ct[0]! ^ ct[ct.length - 1]!;
            }
          });

          rows.push({
            algo,
            mode,
            label,
            op: "encrypt",
            runs,
            sizeBytes: bytes,
            wallMs: enc.wallMs,
            cpuUserMs: enc.cpuUserMs,
            cpuSysMs: enc.cpuSysMs,
            rssDeltaMB: enc.rssDeltaMB,
            heapDeltaMB: enc.heapDeltaMB,
            rssPeakMB: enc.rssPeakMB,
            checksum: checksum >>> 0,
          });
        }

        // ========== DECRYPT ==========
        for (const algo of ["AES", "Twofish", "Blowfish"] as const) {
          let checksum = 0;
          const { cipher, iv } = bench[algo];
          const sample = pre[algo][mode];

          const dec = measure(() => {
            for (let i = 0; i < runs; i++) {
              const pt =
                mode === "ECB"
                  ? ecbDecryptRaw(cipher, sample)
                  : cbcDecryptRaw(cipher, sample, iv);
              checksum ^= pt[0]! ^ pt[pt.length - 1]!;
            }
          });

          rows.push({
            algo,
            mode,
            label,
            op: "decrypt",
            runs,
            sizeBytes: bytes,
            wallMs: dec.wallMs,
            cpuUserMs: dec.cpuUserMs,
            cpuSysMs: dec.cpuSysMs,
            rssDeltaMB: dec.rssDeltaMB,
            heapDeltaMB: dec.heapDeltaMB,
            rssPeakMB: dec.rssPeakMB,
            checksum: checksum >>> 0,
          });
        }
      }
    }
  }

  // ---- Report --------------------------------------------------------------

  console.log(`Node: ${process.version}`);
  console.log(`Platform: ${process.platform} ${process.arch}`);
  console.log(`PID: ${process.pid}`);
  console.log(`(Tip: run with --expose-gc for steadier memory deltas)`);
  console.log(`(RAW modes only; no padding; timings exclude key schedule.)\n`);

  const rowsForTable = rows.map((r) => ({
    algo: r.algo,
    mode: r.mode,
    size: r.label,
    op: r.op,
    runs: r.runs,
    "size (bytes)": r.sizeBytes,
    "time (ms)": format(r.wallMs),
    "cpu user (ms)": format(r.cpuUserMs),
    "cpu sys (ms)": format(r.cpuSysMs),
    "rss Δ (MB)": format(r.rssDeltaMB),
    "heap Δ (MB)": format(r.heapDeltaMB),
    "rss peak (MB)": format(r.rssPeakMB),
    checksum: r.checksum,
  }));
  console.table(rowsForTable);

  // Aggregate throughput (MB/s) hint — uses plaintext size for comparability
  console.log("\nThroughput (approx):");
  const sizeLabels = Array.from(
    new Set(rows.map((r) => r.label))
  ) as Metrics["label"][];
  const modesOrdered: Mode[] = ["ECB", "CBC"];

  for (const algo of ["AES", "Twofish", "Blowfish"] as const) {
    for (const mode of modesOrdered) {
      for (const op of ["encrypt", "decrypt"] as const) {
        for (const label of sizeLabels) {
          const row = rows.find(
            (r) =>
              r.algo === algo &&
              r.mode === mode &&
              r.op === op &&
              r.label === label &&
              r.runs === maxRuns
          )!;
          const totalBytes = row.sizeBytes * row.runs;
          const mbps = totalBytes / (1024 * 1024) / (row.wallMs / 1000);
          console.log(
            `${algo} ${mode} ${op.toUpperCase()} ${label} x${maxRuns} → ~${format(
              mbps,
              2
            )} MB/s`
          );
        }
      }
    }
  }
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

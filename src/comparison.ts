// perf.ts
// Performance harness for the manual AES implementation in ./aes.ts
// Measures wall time, CPU user/sys, and memory deltas for 1/100/1000 runs
// with 3 message lengths using CBC + PKCS#7. No Node 'crypto' used.
//
// Run examples:
//   npx ts-node perf.ts
//   # or (recommended for cleaner memory readings):
//   node --expose-gc -r ts-node/register perf.ts

import {
  ModeOfOperation,
  padding,
  utils,
  AES,
  Counter,
} from "./algorithms/aes.ts";

// ---- small helpers ---------------------------------------------------------

type Metrics = {
  label: string;
  op: "encrypt" | "decrypt";
  runs: number;
  sizeBytes: number;
  wallMs: number;
  cpuUserMs: number;
  cpuSysMs: number;
  rssDeltaMB: number;
  heapDeltaMB: number;
  checksum: number; // anti-DCE sanity
};

const MB = (n: number) => n / (1024 * 1024);

function format(n: number, decimals = 3) {
  return Number.isFinite(n) ? Number(n.toFixed(decimals)) : n;
}

function maybeGC() {
  const g = (global as any).gc as (() => void) | undefined;
  if (g) g();
}

function measure(fn: () => void) {
  maybeGC();
  const mem0 = process.memoryUsage();
  const cpu0 = process.cpuUsage();
  const t0 = process.hrtime.bigint();

  fn();

  const t1 = process.hrtime.bigint();
  const cpu = process.cpuUsage(cpu0);
  const mem1 = process.memoryUsage();

  return {
    wallMs: Number(t1 - t0) / 1e6,
    cpuUserMs: cpu.user / 1000,
    cpuSysMs: cpu.system / 1000,
    rssDeltaMB: MB(mem1.rss - mem0.rss),
    heapDeltaMB: MB(mem1.heapUsed - mem0.heapUsed),
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
  const key = prng(16); // AES-128
  const iv = prng(16); // 16B IV for CBC

  // Three message sizes
  const sizes = [
    { label: "16B", bytes: 16 },
    { label: "4KiB", bytes: 4 * 1024 },
    { label: "1MiB", bytes: 1 * 1024 * 1024 },
  ];

  // Run counts
  const runsArr = [1, 100, 1000];

  // Warm up JIT a bit (doesn't affect the measured loops)
  {
    const warmCBC = new ModeOfOperation.cbc(key, iv);
    const warm = padding.pkcs7.pad(prng(256));
    for (let i = 0; i < 50; i++) {
      const ct = warmCBC.encrypt(warm);
      const pt = new ModeOfOperation.cbc(key, iv).decrypt(ct);
      padding.pkcs7.strip(pt);
    }
  }

  const rows: Metrics[] = [];

  for (const { label, bytes } of sizes) {
    // Prepare deterministic plaintext and padding
    const plain = prng(bytes);
    const padded = padding.pkcs7.pad(plain);

    // Precompute a single ciphertext to reuse in decrypt loops
    const cbcOnce = new ModeOfOperation.cbc(key, iv);
    const ciphertextSample = cbcOnce.encrypt(padded);

    // Correctness check once
    {
      const decOnce = new ModeOfOperation.cbc(key, iv).decrypt(
        ciphertextSample
      );
      const unpadded = padding.pkcs7.strip(decOnce);
      const ok =
        unpadded.length === plain.length &&
        unpadded.every((b, i) => b === plain[i]);
      if (!ok) {
        throw new Error("Decrypt correctness check failed (CBC/PKCS#7).");
      }
    }

    for (const runs of runsArr) {
      // --- ENCRYPT ----------------------------------------------------------
      let encChecksum = 0;
      const encMetrics = measure(() => {
        for (let i = 0; i < runs; i++) {
          const cbc = new ModeOfOperation.cbc(key, iv); // fresh IV each time
          const ct = cbc.encrypt(padded);
          // cheap checksum so results can't be optimized away
          encChecksum ^= ct[0] ^ ct[ct.length - 1];
        }
      });

      rows.push({
        label,
        op: "encrypt",
        runs,
        sizeBytes: bytes,
        wallMs: encMetrics.wallMs,
        cpuUserMs: encMetrics.cpuUserMs,
        cpuSysMs: encMetrics.cpuSysMs,
        rssDeltaMB: encMetrics.rssDeltaMB,
        heapDeltaMB: encMetrics.heapDeltaMB,
        checksum: encChecksum >>> 0,
      });

      // --- DECRYPT ----------------------------------------------------------
      let decChecksum = 0;
      const decMetrics = measure(() => {
        for (let i = 0; i < runs; i++) {
          const cbc = new ModeOfOperation.cbc(key, iv);
          const ptPadded = cbc.decrypt(ciphertextSample);
          const pt = padding.pkcs7.strip(ptPadded);
          decChecksum ^= pt[0] ^ pt[pt.length - 1];
        }
      });

      rows.push({
        label,
        op: "decrypt",
        runs,
        sizeBytes: bytes,
        wallMs: decMetrics.wallMs,
        cpuUserMs: decMetrics.cpuUserMs,
        cpuSysMs: decMetrics.cpuSysMs,
        rssDeltaMB: decMetrics.rssDeltaMB,
        heapDeltaMB: decMetrics.heapDeltaMB,
        checksum: decChecksum >>> 0,
      });
    }
  }

  // ---- Report --------------------------------------------------------------

  console.log(`Node: ${process.version}`);
  console.log(`Platform: ${process.platform} ${process.arch}`);
  console.log(`PID: ${process.pid}`);
  console.log(`(Tip: run with --expose-gc for steadier memory deltas)\n`);

  // pretty table
  const table = rows.map((r) => ({
    size: r.label,
    op: r.op,
    runs: r.runs,
    "size (bytes)": r.sizeBytes,
    "time (ms)": format(r.wallMs),
    "cpu user (ms)": format(r.cpuUserMs),
    "cpu sys (ms)": format(r.cpuSysMs),
    "rss Δ (MB)": format(r.rssDeltaMB),
    "heap Δ (MB)": format(r.heapDeltaMB),
    checksum: r.checksum,
  }));

  console.table(table);

  // Aggregate throughput (MB/s) hint
  console.log("\nThroughput (approx):");
  for (const op of ["encrypt", "decrypt"] as const) {
    for (const { label } of sizes) {
      // pick the 1000-run row for each size/op
      const row = rows.find(
        (r) => r.op === op && r.label === label && r.runs === 1000
      )!;
      const totalBytes = row.sizeBytes * row.runs;
      const mbps = totalBytes / (1024 * 1024) / (row.wallMs / 1000);
      console.log(
        `${op.toUpperCase()} ${label} x1000 → ~${format(mbps, 2)} MB/s`
      );
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

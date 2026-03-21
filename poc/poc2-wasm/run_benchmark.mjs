// Node.js benchmark runner for POC 2 WASM module
// Run: node run_benchmark.mjs

import { run_dkg, run_full_test } from './pkg/poc2_wasm.js';

console.log("=== POC 2: WASM Benchmark ===\n");

// Measure DKG-only timing
console.log("--- DKG only (no aux info, no signing) ---");
const dkg_start = performance.now();
const pubkey = run_dkg();
const dkg_elapsed = performance.now() - dkg_start;
console.log(`  DKG pubkey: ${pubkey}`);
console.log(`  DKG time: ${dkg_elapsed.toFixed(0)}ms\n`);

// Measure full test with internal timings
console.log("--- Full test: DKG + aux gen + signing + presigning ---");
const full_start = performance.now();
const result = run_full_test();
const full_elapsed = performance.now() - full_start;

// Parse timings from result string
const timingsPart = result.split(" | ")[1];
console.log(`  ${timingsPart}`);
console.log(`  Total wall time: ${full_elapsed.toFixed(0)}ms\n`);

// Memory usage
const mem = process.memoryUsage();
console.log("--- Memory usage ---");
console.log(`  RSS: ${(mem.rss / 1024 / 1024).toFixed(1)}MB`);
console.log(`  Heap used: ${(mem.heapUsed / 1024 / 1024).toFixed(1)}MB`);
console.log(`  Heap total: ${(mem.heapTotal / 1024 / 1024).toFixed(1)}MB`);
console.log(`  External: ${(mem.external / 1024 / 1024).toFixed(1)}MB`);

// WASM module size
import { statSync } from 'fs';
const wasmSize = statSync('./pkg/poc2_wasm_bg.wasm').size;
console.log(`\n--- WASM module ---`);
console.log(`  Size: ${(wasmSize / 1024).toFixed(0)}KB (${(wasmSize / 1024 / 1024).toFixed(2)}MB)`);

console.log("\n=== POC 2 VERDICT ===");
console.log(`  [${pubkey.length === 66 ? 'x' : ' '}] DKG produces valid pubkey`);
console.log(`  [${result.startsWith('PASS') ? 'x' : ' '}] Full signing works in WASM`);
console.log(`  [${wasmSize < 50 * 1024 * 1024 ? 'x' : ' '}] Module < 50MB (${(wasmSize / 1024).toFixed(0)}KB)`);
console.log(`  [${mem.rss < 128 * 1024 * 1024 ? 'x' : ' '}] Memory < 128MB (${(mem.rss / 1024 / 1024).toFixed(1)}MB RSS)`);

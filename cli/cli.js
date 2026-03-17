#!/usr/bin/env node
/**
 * icb — ic-certified-blockchain CLI
 *
 * Usage: icb [global options] <command> [options] [args]
 *
 * Configuration is read from .env in this directory; all values can be
 * overridden with command-line flags.
 */

import { Command } from 'commander';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import sha256lib from 'sha256';
import { IDL } from '@icp-sdk/core/candid';
import { Principal } from '@icp-sdk/core/principal';
import { Secp256k1KeyIdentity } from '@icp-sdk/core/identity/secp256k1';
import {
  Actor, Cbor, Certificate, HttpAgent, lookup_path, reconstruct,
} from '@icp-sdk/core/agent';
import { idlFactory } from '../src/declarations/ic-certified-blockchain/ic-certified-blockchain.did.js';

// ── Env ─────────────────────────────────────────────────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) dotenv.config({ path: envPath });

global.fetch = fetch;

// ── Candid Block type (must match src/main.rs Block struct) ─────────────────
const BlockIDL = IDL.Record({
  certificate:   IDL.Vec(IDL.Nat8),
  data:          IDL.Vec(IDL.Vec(IDL.Nat8)),
  tree:          IDL.Vec(IDL.Nat8),
  callers:       IDL.Vec(IDL.Principal),
  previous_hash: IDL.Vec(IDL.Nat8),
});

// ── Utilities ────────────────────────────────────────────────────────────────

function die(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  if (!/^([0-9a-f]{2})*$/i.test(hex)) throw new Error(`invalid hex: ${hex}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function isEqBuf(a, b) {
  const u = new Uint8Array(a), v = new Uint8Array(b);
  if (u.length !== v.length) return false;
  for (let i = 0; i < u.length; i++) if (u[i] !== v[i]) return false;
  return true;
}

function sha256bytes(data) {
  return fromHex(sha256lib(data));
}

function mergeU8(a, b) {
  const m = new Uint8Array(a.length + b.length);
  m.set(a); m.set(b, a.length);
  return m;
}

// sha256(sha256(caller) || sha256(data))  — mirrors hash_pending() in Rust
function entryHash(callerU8, dataU8) {
  return sha256bytes(mergeU8(sha256bytes(callerU8), sha256bytes(dataU8)));
}

// sha256(IDL.encode([BlockIDL], [block]))  — mirrors get_previous_hash() in Rust
function blockHash(block) {
  const enc = IDL.encode([BlockIDL], [block]);
  return sha256bytes(new Uint8Array(enc));
}

function tryUtf8(buf) {
  const s = Buffer.from(buf).toString('utf8');
  return /^[\x09\x0a\x0d\x20-\x7e]*$/.test(s) ? s : null;
}

function fmtData(rawBuf) {
  const d = new Uint8Array(rawBuf);
  const utf = tryUtf8(d);
  if (utf !== null) return `"${utf.replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
  return `<${d.length} bytes 0x${toHex(d).slice(0, 32)}${d.length > 16 ? '…' : ''}>`;
}

function printBlock(index, block, { verbose = false } = {}) {
  const n = block.data.length;
  console.log(`Block #${index}  [${n} entr${n === 1 ? 'y' : 'ies'}]`);
  console.log(`  previous_hash : ${toHex(block.previous_hash)}`);
  for (let i = 0; i < n; i++) {
    const caller = block.callers[i]?.toText?.() ?? String(block.callers[i]);
    console.log(`  entry[${i}]`);
    console.log(`    caller : ${caller}`);
    console.log(`    data   : ${fmtData(block.data[i])}`);
    if (verbose) console.log(`    sha256 : ${toHex(sha256bytes(new Uint8Array(block.data[i])))}`);
  }
  if (verbose) {
    console.log(`  certificate  : ${toHex(block.certificate).slice(0, 64)}…`);
    console.log(`  tree         : ${toHex(block.tree).slice(0, 64)}…`);
  }
}

// ── Snapshot serialisation ───────────────────────────────────────────────────

function blockToSnap(index, block) {
  return {
    index:         Number(index),
    certificate:   toHex(block.certificate),
    tree:          toHex(block.tree),
    data:          [...block.data].map(d => toHex(d)),
    callers:       [...block.callers].map(p => p?.toText?.() ?? String(p)),
    previous_hash: toHex(block.previous_hash),
  };
}

function snapToBlock(obj) {
  return {
    certificate:   fromHex(obj.certificate),
    tree:          fromHex(obj.tree),
    data:          obj.data.map(h => fromHex(h)),
    callers:       obj.callers.map(p => Principal.fromText(p)),
    previous_hash: fromHex(obj.previous_hash),
  };
}

// ── Config / Actor ───────────────────────────────────────────────────────────

function resolveCanisterId(override) {
  if (override) return override;
  if (process.env.IC_CANISTER_ID) return process.env.IC_CANISTER_ID;
  // Walk up from cwd looking for .dfx/local/canister_ids.json
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const p = path.join(dir, '.dfx', 'local', 'canister_ids.json');
    if (fs.existsSync(p)) {
      const id = JSON.parse(fs.readFileSync(p, 'utf8'))['ic-certified-blockchain']?.local;
      if (id) return id;
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  die('canister ID not found — set IC_CANISTER_ID in .env or run dfx deploy first');
}

function loadIdentity(file) {
  const f = file ?? process.env.IC_IDENTITY_FILE;
  if (!f) return null;
  // Resolve ~ → $HOME; relative paths → relative to cli/ directory
  const resolved = f.startsWith('~')
    ? path.join(process.env.HOME ?? '', f.slice(1))
    : path.isAbsolute(f) ? f : path.join(__dirname, f);
  if (!fs.existsSync(resolved)) die(`identity file not found: ${resolved}`);
  const pem = fs.readFileSync(resolved);
  const keyObj = crypto.createPrivateKey({ key: pem, format: 'pem' });
  const der = keyObj.export({ format: 'der', type: 'sec1' });
  const PREFIX = Buffer.from([0x30, 0x74, 0x02, 0x01, 0x01, 0x04, 0x20]);
  if (!Buffer.from(der).subarray(0, 7).equals(PREFIX))
    die('unsupported identity format (expected secp256k1 SEC1 — use: dfx identity export <name>)');
  return Secp256k1KeyIdentity.fromSecretKey(new Uint8Array(der.slice(7, 39)));
}

async function makeActor(globalOpts) {
  const network    = globalOpts.network;
  const production = globalOpts.production;
  const canisterId = resolveCanisterId(globalOpts.canister);
  const identity   = loadIdentity(globalOpts.identity);

  const agentOptions = { host: network };
  if (identity) agentOptions.identity = identity;

  const agent = new HttpAgent(agentOptions);
  if (!production) await agent.fetchRootKey();

  const actor = Actor.createActor(idlFactory, { agent, canisterId });
  return { actor, agent, canisterId, network, identity };
}

// ── Safe append ──────────────────────────────────────────────────────────────

async function safeAppend(actor, entries) {
  // Commit any previously staged data before staging ours
  const pending = await actor.get_certificate();
  if (pending.length > 0) {
    console.log('Note: committing previously staged data first…');
    const committed = await actor.commit(pending[0]);
    if (committed.length > 0) {
      console.log(`  Committed pending block at index ${committed[0]}`);
    } else {
      console.warn('  Warning: commit returned None (stale certificate, staged data discarded)');
    }
  }

  console.log(`Staging ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}…`);
  let certified;
  try {
    certified = await actor.prepare(entries);
  } catch (e) {
    // Concurrent prepare raced us — commit the other writer's data then retry
    const cert2 = await actor.get_certificate();
    if (cert2.length === 0) throw e;
    console.warn('  Race detected; committing concurrent staged data and retrying…');
    await actor.commit(cert2[0]);
    certified = await actor.prepare(entries);
  }
  console.log(`  certified_data: ${toHex(certified).slice(0, 32)}…`);

  const cert = await actor.get_certificate();
  if (!cert || cert.length === 0) die('get_certificate() returned None after prepare()');

  const result = await actor.commit(cert[0]);
  if (!result || result.length === 0) die('commit() returned None after certificate obtained');

  return result[0];
}

// ── Block verification ───────────────────────────────────────────────────────

async function verifyBlock(index, block, rootKey, canisterId) {
  const errors = [];
  const canisterPrincipal = typeof canisterId === 'string'
    ? Principal.fromText(canisterId) : canisterId;
  const canisterIdStr = typeof canisterId === 'string' ? canisterId : canisterId.toText();

  // 1. IC certificate signature
  let cert;
  try {
    cert = await Certificate.create({
      certificate: block.certificate instanceof Uint8Array
        ? block.certificate : new Uint8Array(block.certificate),
      canisterId: canisterIdStr,
      rootKey,
      principal: { canisterId: canisterPrincipal },
      disableTimeVerification: true, // certificates in stored blocks can be arbitrarily old
    });
  } catch (e) {
    errors.push(`certificate signature invalid: ${e.message}`);
    return { ok: false, errors };
  }

  // 2. certified_data == reconstructed tree hash
  const certifiedData = cert.lookup_path([
    'canister', canisterPrincipal.toUint8Array(), 'certified_data',
  ]).value;
  if (!certifiedData) {
    errors.push('certified_data not found in certificate');
    return { ok: false, errors };
  }
  const blockTree = Cbor.decode(
    block.tree instanceof Uint8Array ? block.tree : new Uint8Array(block.tree)
  );
  const reconstructed = await reconstruct(blockTree);
  if (!isEqBuf(certifiedData, reconstructed))
    errors.push('certified_data ≠ reconstructed tree hash');

  // 3. Entry hashes in Merkle tree
  for (let i = 0; i < block.data.length; i++) {
    const key = new Uint8Array(4);
    new DataView(key.buffer).setUint32(0, i, false); // big-endian (wasm32 usize)
    const treeHash = lookup_path(['certified_blocks', key], blockTree).value;
    if (!treeHash) { errors.push(`entry[${i}] not found in tree`); continue; }
    const caller = block.callers[i];
    const callerBytes = caller instanceof Principal ? caller.toUint8Array()
      : typeof caller === 'string' ? Principal.fromText(caller).toUint8Array()
      : new Uint8Array(caller);
    const dataBytes = block.data[i] instanceof Uint8Array
      ? block.data[i] : new Uint8Array(block.data[i]);
    const expected = entryHash(callerBytes, dataBytes);
    if (!isEqBuf(new Uint8Array(treeHash), expected))
      errors.push(`entry[${i}] hash mismatch in tree`);
  }

  // 4. previous_hash field matches certified value in tree
  const phKey = new TextEncoder().encode('previous_hash');
  const treePh = lookup_path(['certified_blocks', phKey], blockTree).value;
  if (!treePh) {
    errors.push('previous_hash not found in tree');
  } else {
    const blockPh = block.previous_hash instanceof Uint8Array
      ? block.previous_hash : new Uint8Array(block.previous_hash);
    if (!isEqBuf(new Uint8Array(treePh), blockPh))
      errors.push('previous_hash in tree ≠ block.previous_hash');
  }

  return { ok: errors.length === 0, errors };
}

// ── Chain hash verification ──────────────────────────────────────────────────
// Verifies: block[i].previous_hash == sha256(IDL.encode(block[i-1]))

function verifyChainHashes(blocks) {
  const issues = [];
  if (blocks.length > 0) {
    const ph = new Uint8Array(blocks[0].block.previous_hash);
    if (!ph.every(b => b === 0))
      console.log(`  Note: block ${blocks[0].index} has non-zero previous_hash (chain continuation from prior segment)`);
  }
  for (let i = 1; i < blocks.length; i++) {
    if (blocks[i].index !== blocks[i - 1].index + 1) continue; // non-contiguous range, skip
    const actualPh = new Uint8Array(blocks[i].block.previous_hash);
    const expectedPh = blockHash(blocks[i - 1].block);
    if (!isEqBuf(expectedPh, actualPh)) {
      issues.push(
        `Block ${blocks[i].index}: previous_hash mismatch ` +
        `(expected ${toHex(expectedPh).slice(0, 16)}… ` +
        `got ${toHex(actualPh).slice(0, 16)}…)`
      );
    }
  }
  return issues;
}

// ── Program ──────────────────────────────────────────────────────────────────

const program = new Command();
program
  .name('icb')
  .description('ic-certified-blockchain CLI')
  .option('--network <url>',   'IC network URL',
    process.env.IC_NETWORK || 'http://localhost:8080')
  .option('--identity <file>', 'Identity PEM file',
    process.env.IC_IDENTITY_FILE)
  .option('--canister <id>',   'Canister ID',
    process.env.IC_CANISTER_ID)
  .option('--production',      'Production mode (use mainnet root key, skip fetchRootKey)',
    process.env.IC_PRODUCTION === 'true');

// ── status ───────────────────────────────────────────────────────────────────
program.command('status')
  .description('Show blockchain status (first, mid, next, last_hash, staged, authorized)')
  .action(async () => {
    const { actor, canisterId, network } = await makeActor(program.opts());
    const [first, mid, next, lastHash, auths, staged] = await Promise.all([
      actor.first(), actor.mid(), actor.next(), actor.last_hash(),
      actor.get_authorized(), actor.get_certificate(),
    ]);
    console.log(`network    : ${network}`);
    console.log(`canister   : ${canisterId}`);
    console.log(`first      : ${first}`);
    console.log(`mid        : ${mid}`);
    console.log(`next       : ${next}`);
    console.log(`blocks     : ${next - first}`);
    console.log(`last_hash  : ${lastHash}`);
    console.log(`staged     : ${staged.length > 0 ? 'yes (pending commit)' : 'no'}`);
    console.log(`authorized : ${auths.length}`);
    for (const a of auths) {
      const role = 'Admin' in a.auth ? 'Admin' : 'User';
      console.log(`  ${a.id.toText()}  [${role}]`);
    }
  });

// ── append ───────────────────────────────────────────────────────────────────
program.command('append [entries...]')
  .description('Safely append a block; each arg becomes one blob entry')
  .option('-f, --file <path>', 'Add file contents as an entry (repeatable)',
    (v, a) => [...a, v], [])
  .option('-x, --hex <hex>',  'Add hex-encoded bytes as an entry (repeatable)',
    (v, a) => [...a, v], [])
  .action(async (textEntries, opts) => {
    const { actor } = await makeActor(program.opts());
    const entries = [];
    for (const t of textEntries)  entries.push(new TextEncoder().encode(t));
    for (const h of opts.hex)     entries.push(fromHex(h));
    for (const f of opts.file) {
      if (!fs.existsSync(f)) die(`file not found: ${f}`);
      entries.push(new Uint8Array(fs.readFileSync(f)));
    }
    if (entries.length === 0)
      die('no entries — provide text args, --file <path>, or --hex <hex>');

    const index = await safeAppend(actor, entries);
    console.log(`Block appended at index ${index}`);
  });

// ── get ──────────────────────────────────────────────────────────────────────
program.command('get <index>')
  .description('Get and display a block')
  .option('-v, --verbose', 'Show certificate/tree excerpts and entry sha256')
  .option('--verify',      'Also verify the block certificate')
  .option('--raw',         'Output raw JSON (snapshot format)')
  .action(async (indexStr, opts) => {
    const { actor, agent, canisterId } = await makeActor(program.opts());
    const index = BigInt(indexStr);
    let block;
    try { block = await actor.get_block(index); }
    catch (e) { die(`get_block(${index}) failed: ${e.message}`); }

    if (opts.raw) {
      console.log(JSON.stringify(blockToSnap(index, block), null, 2));
      return;
    }
    printBlock(index, block, { verbose: opts.verbose });

    if (opts.verify) {
      process.stdout.write('Verifying… ');
      const { ok, errors } = await verifyBlock(index, block, agent.rootKey, canisterId);
      if (ok) console.log('OK');
      else { console.log('FAIL'); for (const e of errors) console.log(`  ! ${e}`); }
    }
  });

// ── find ─────────────────────────────────────────────────────────────────────
program.command('find <query>')
  .description('Find block(s) by data hash; <query> is text by default')
  .option('-f, --file',    'Hash the contents of the file at <query>')
  .option('-x, --hex',     'Treat <query> as a raw 32-byte hex hash (no sha256)')
  .option('-v, --verbose', 'Print the block after finding it')
  .action(async (query, opts) => {
    const { actor } = await makeActor(program.opts());
    let hash;
    if (opts.hex) {
      hash = fromHex(query);
      if (hash.length !== 32) die('--hex hash must be 32 bytes (64 hex chars)');
    } else if (opts.file) {
      if (!fs.existsSync(query)) die(`file not found: ${query}`);
      hash = sha256bytes(new Uint8Array(fs.readFileSync(query)));
    } else {
      hash = sha256bytes(new TextEncoder().encode(query));
    }

    const result = await actor.find(hash);
    if (result.length === 0) { console.log('Not found'); return; }
    const index = result[0];
    console.log(`Found at block ${index}`);
    if (opts.verbose) {
      const block = await actor.get_block(index);
      printBlock(index, block, { verbose: true });
    }
  });

// ── download ─────────────────────────────────────────────────────────────────
program.command('download')
  .description('Download blocks to individual JSON files')
  .option('-s, --start <n>',    'Start index (default: first())')
  .option('-e, --end <n>',      'End index inclusive (default: next()-1)')
  .option('-o, --output <dir>', 'Output directory', './blocks')
  .action(async (opts) => {
    const { actor } = await makeActor(program.opts());
    const first = await actor.first();
    const next  = await actor.next();
    if (next === first) { console.log('Blockchain is empty.'); return; }
    const start = opts.start !== undefined ? BigInt(opts.start) : first;
    const end   = opts.end   !== undefined ? BigInt(opts.end)   : next - 1n;
    if (start > end)    die(`start (${start}) > end (${end})`);
    if (start < first)  die(`start (${start}) < first() (${first})`);
    if (end >= next)    die(`end (${end}) >= next() (${next})`);
    fs.mkdirSync(opts.output, { recursive: true });
    console.log(`Downloading blocks ${start}..${end} → ${opts.output}/`);
    for (let i = start; i <= end; i++) {
      const block = await actor.get_block(i);
      fs.writeFileSync(
        path.join(opts.output, `block-${i}.json`),
        JSON.stringify(blockToSnap(i, block), null, 2)
      );
      process.stdout.write(`  ${i}/${end}\r`);
    }
    console.log(`Downloaded ${end - start + 1n} block(s) to ${opts.output}/`);
  });

// ── snapshot ─────────────────────────────────────────────────────────────────
program.command('snapshot')
  .description('Download the blockchain to a single JSON snapshot file')
  .option('-s, --start <n>',     'Start index (default: first())')
  .option('-e, --end <n>',       'End index inclusive (default: next()-1)')
  .option('-o, --output <file>', 'Output file (default: blockchain-<timestamp>.json)')
  .action(async (opts) => {
    const { actor, agent, canisterId, network } = await makeActor(program.opts());
    const first = await actor.first();
    const next  = await actor.next();
    if (next === first) { console.log('Blockchain is empty.'); return; }
    const start = opts.start !== undefined ? BigInt(opts.start) : first;
    const end   = opts.end   !== undefined ? BigInt(opts.end)   : next - 1n;
    const ts    = new Date().toISOString().replace(/[:.]/g, '-');
    const outFile = opts.output ?? `blockchain-${ts}.json`;

    console.log(`Snapshotting blocks ${start}..${end} → ${outFile}`);
    const snap = {
      version:   1,
      canisterId,
      rootKey:   toHex(agent.rootKey ?? new Uint8Array(0)),
      network,
      createdAt: new Date().toISOString(),
      first:     Number(first),
      next:      Number(next),
      blocks:    [],
    };
    for (let i = start; i <= end; i++) {
      snap.blocks.push(blockToSnap(i, await actor.get_block(i)));
      process.stdout.write(`  ${i}/${end}\r`);
    }
    console.log();
    fs.writeFileSync(outFile, JSON.stringify(snap, null, 2));
    console.log(`${snap.blocks.length} block(s) saved to ${outFile}`);
  });

// ── verify helpers ───────────────────────────────────────────────────────────

// Load records from a local path (snapshot file, single block file, or directory).
// Returns { records, canisterId, rootKey, label } where canisterId/rootKey may be
// null if the source doesn't contain them (single files / directories).
function loadLocalBlocks(inputPath, opts) {
  const stat = fs.statSync(inputPath);

  if (stat.isDirectory()) {
    const files = fs.readdirSync(inputPath)
      .filter(f => /^block-\d+\.json$/.test(f))
      .sort((a, b) => parseInt(a.match(/(\d+)/)[1]) - parseInt(b.match(/(\d+)/)[1]));
    if (files.length === 0) die(`no block-*.json files found in ${inputPath}`);
    let records = files.map(f => {
      const obj = JSON.parse(fs.readFileSync(path.join(inputPath, f), 'utf8'));
      return { index: obj.index, block: snapToBlock(obj) };
    });
    const start = opts.start !== undefined ? Number(opts.start) : records[0].index;
    const end   = opts.end   !== undefined ? Number(opts.end)   : records[records.length - 1].index;
    records = records.filter(r => r.index >= start && r.index <= end);
    return { records, canisterId: null, rootKey: null,
      label: `directory ${inputPath}  (${records.length} block(s), indices ${start}..${end})` };
  }

  const content = JSON.parse(fs.readFileSync(inputPath, 'utf8'));

  // Snapshot file produced by `icb snapshot`
  if (content.version && Array.isArray(content.blocks)) {
    if (!content.canisterId) die('snapshot missing canisterId');
    if (!content.rootKey)    die('snapshot missing rootKey (re-snapshot with this CLI)');
    const start = opts.start !== undefined ? Number(opts.start) : content.first;
    const end   = opts.end   !== undefined ? Number(opts.end)   : content.next - 1;
    const records = content.blocks
      .filter(b => b.index >= start && b.index <= end)
      .map(b => ({ index: b.index, block: snapToBlock(b) }));
    return { records, canisterId: content.canisterId, rootKey: fromHex(content.rootKey),
      label: `snapshot ${inputPath}  (blocks ${start}..${end})` };
  }

  // Single block file produced by `icb download`
  if (content.index !== undefined && content.certificate !== undefined) {
    return { records: [{ index: content.index, block: snapToBlock(content) }],
      canisterId: null, rootKey: null, label: `block file ${inputPath}` };
  }

  die(`unrecognised file format: ${inputPath}`);
}

// ── verify ───────────────────────────────────────────────────────────────────
program.command('verify [path]')
  .description(
    'Verify blockchain integrity.\n' +
    '  <path> can be: a snapshot file, a single block-N.json file, or a directory\n' +
    '  of block-*.json files.  Omit <path> to verify the live chain.'
  )
  .option('-s, --start <n>',    'Start index (default: first in source)')
  .option('-e, --end <n>',      'End index inclusive (default: last in source)')
  .option('--no-chain',         'Skip previous_hash chain re-derivation')
  .option('--root-key <hex>',   'Root key for fully offline verification (hex DER)')
  .action(async (inputPath, opts) => {
    let records = [];
    let rootKey, canisterId;

    if (!inputPath) {
      // ── Live chain ──────────────────────────────────────────────────────────
      const ctx = await makeActor(program.opts());
      canisterId = ctx.canisterId;
      rootKey    = ctx.agent.rootKey;
      const first = await ctx.actor.first();
      const next  = await ctx.actor.next();
      const start = opts.start !== undefined ? BigInt(opts.start) : first;
      const end   = opts.end   !== undefined ? BigInt(opts.end)   : next - 1n;
      console.log(`Verifying live chain: blocks ${start}..${end}`);
      for (let i = start; i <= end; i++) {
        records.push({ index: Number(i), block: await ctx.actor.get_block(i) });
        process.stdout.write(`  fetching ${i}/${end}\r`);
      }
      console.log();
    } else {
      // ── Local file or directory ─────────────────────────────────────────────
      if (!fs.existsSync(inputPath)) die(`not found: ${inputPath}`);
      const loaded = loadLocalBlocks(inputPath, opts);
      records    = loaded.records;
      canisterId = loaded.canisterId;
      rootKey    = loaded.rootKey;
      console.log(`Verifying ${loaded.label}`);

      // Root key: snapshot supplies it; otherwise use --root-key or fetch live
      if (!rootKey) {
        if (opts.rootKey) {
          rootKey = fromHex(opts.rootKey);
        } else {
          process.stdout.write('Fetching root key from network… ');
          const ctx = await makeActor(program.opts());
          rootKey = ctx.agent.rootKey;
          if (!canisterId) canisterId = ctx.canisterId;
          console.log('OK');
        }
      }
      // canisterId: snapshot supplies it; otherwise resolve from global opts / dfx
      if (!canisterId) canisterId = resolveCanisterId(program.opts().canister);
    }

    if (records.length === 0) { console.log('No blocks in range.'); return; }

    // Per-block certificate + Merkle verification
    let pass = 0, fail = 0;
    for (const { index, block } of records) {
      process.stdout.write(`  Block ${index}: `);
      const { ok, errors } = await verifyBlock(index, block, rootKey, canisterId);
      if (ok) { console.log('OK'); pass++; }
      else    { console.log('FAIL'); errors.forEach(e => console.log(`    ! ${e}`)); fail++; }
    }

    // Hash chain verification (previous_hash == sha256(candid_encode(prev_block)))
    if (opts.chain !== false) {
      console.log('Checking hash chain…');
      const chainIssues = verifyChainHashes(records);
      if (chainIssues.length === 0) {
        console.log('  Hash chain: OK');
      } else {
        for (const issue of chainIssues) { console.log(`  ! ${issue}`); fail++; }
      }
    }

    console.log(`\nResult: ${pass} OK, ${fail} FAIL  (${records.length} block(s))`);
    if (fail > 0) process.exit(1);
    console.log('Verification complete.');
  });

// ── rotate ───────────────────────────────────────────────────────────────────
program.command('rotate')
  .description('Rotate the log: primary→secondary, clear old secondary')
  .action(async () => {
    const { actor } = await makeActor(program.opts());
    const [first, mid, next] = await Promise.all([
      actor.first(), actor.mid(), actor.next(),
    ]);
    console.log(`Before: first=${first} mid=${mid} next=${next}`);
    const result = await actor.rotate();
    const [first2, mid2, next2] = await Promise.all([
      actor.first(), actor.mid(), actor.next(),
    ]);
    console.log(`After : first=${first2} mid=${mid2} next=${next2}`);
    if (result.length > 0) {
      console.log(`Rotated. New first (deleted up to): ${result[0]}`);
    } else {
      console.log('Rotated. Secondary was empty; nothing deleted.');
    }
  });

// ── auth ─────────────────────────────────────────────────────────────────────
const auth = program.command('auth').description('Manage authorized principals');

auth.command('list')
  .description('List authorized principals')
  .action(async () => {
    const { actor } = await makeActor(program.opts());
    const auths = await actor.get_authorized();
    if (auths.length === 0) { console.log('No authorized principals.'); return; }
    const pad = Math.max(...auths.map(a => a.id.toText().length));
    for (const a of auths) {
      const role = 'Admin' in a.auth ? 'Admin' : 'User';
      console.log(`${a.id.toText().padEnd(pad)}  [${role}]`);
    }
  });

auth.command('add <principal>')
  .description('Authorize a principal (default role: User)')
  .option('--admin', 'Grant Admin role instead of User')
  .action(async (principalStr, opts) => {
    const { actor } = await makeActor(program.opts());
    const p    = Principal.fromText(principalStr);
    const role = opts.admin ? { Admin: null } : { User: null };
    await actor.authorize(p, role);
    console.log(`Authorized ${principalStr} as ${opts.admin ? 'Admin' : 'User'}`);
  });

auth.command('remove <principal>')
  .description('Deauthorize a principal')
  .action(async (principalStr) => {
    const { actor } = await makeActor(program.opts());
    await actor.deauthorize(Principal.fromText(principalStr));
    console.log(`Deauthorized ${principalStr}`);
  });

// ── run ──────────────────────────────────────────────────────────────────────

function fmtError(e) {
  // IC agent errors include a verbose JSON body; extract the human-readable part
  const msg = e.message ?? String(e);
  const rejectMatch = msg.match(/Reject text: ([^\n]+)/);
  if (rejectMatch) return rejectMatch[1].trim();
  // Trim everything after a large JSON blob
  const trimmed = msg.split('\n').slice(0, 6).join('\n');
  return trimmed.length < msg.length ? trimmed + '\n…' : msg;
}

program.parseAsync(process.argv).catch(e => {
  console.error(`error: ${fmtError(e)}`);
  process.exit(1);
});

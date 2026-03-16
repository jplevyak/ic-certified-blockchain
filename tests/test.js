import fetch from 'node-fetch';
import fs from 'fs';
import crypto from 'crypto';
import sha256 from "sha256";
import { lebDecode, PipeArrayBuffer } from "@icp-sdk/core/candid";
import { Principal } from '@icp-sdk/core/principal';
import { Secp256k1KeyIdentity } from '@icp-sdk/core/identity/secp256k1';
import { Actor, Cbor, Certificate, HttpAgent, lookup_path, reconstruct } from '@icp-sdk/core/agent';
import { idlFactory } from '../src/declarations/ic-certified-blockchain/ic-certified-blockchain.did.js';
import exec from 'await-exec';
import assert from 'assert';

// ============================================================
// Utility functions
// ============================================================

function toHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex) {
  const hexRe = new RegExp(/^([0-9A-F]{2})*$/i);
  if (!hexRe.test(hex)) throw new Error("Invalid hexadecimal string.");
  return new Uint8Array([...hex].reduce((acc, curr, i) => {
    acc[(i / 2) | 0] = (acc[(i / 2) | 0] || "") + curr;
    return acc;
  }, []).map(x => Number.parseInt(x, 16))).buffer;
}

function mergeUInt8Arrays(a1, a2) {
  const merged = new Uint8Array(a1.length + a2.length);
  merged.set(a1);
  merged.set(a2, a1.length);
  return merged;
}

function isBufferEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  const a8 = new Uint8Array(a);
  const b8 = new Uint8Array(b);
  for (let i = 0; i < a8.length; i++) {
    if (a8[i] !== b8[i]) return false;
  }
  return true;
}

// Entry hash: sha256(sha256(caller) || sha256(data))  — matches hash_pending() in Rust
function entryHash(callerBytes, dataBytes) {
  const callerHash = new Uint8Array(fromHex(sha256(callerBytes)));
  const dataHash   = new Uint8Array(fromHex(sha256(dataBytes)));
  return new Uint8Array(fromHex(sha256(mergeUInt8Arrays(callerHash, dataHash))));
}

// ============================================================
// Minimal test runner
// ============================================================

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL: ${name}`);
    console.log(`        ${e.message || e}`);
    failed++;
  }
}

function assertEq(actual, expected, msg) {
  if (actual !== expected)
    throw new Error(`${msg || 'assertEq'}: expected ${expected}, got ${actual}`);
}

function assertBufEq(actual, expected, msg) {
  if (!isBufferEqual(actual, expected))
    throw new Error(`${msg || 'assertBufEq'}: expected ${toHex(expected)}, got ${toHex(actual)}`);
}

function assertSome(opt, msg) {
  if (!opt || opt.length === 0)
    throw new Error(`${msg || 'assertSome'}: expected Some, got None`);
  return opt[0];
}

function assertNone(opt, msg) {
  if (opt && opt.length > 0)
    throw new Error(`${msg || 'assertNone'}: expected None, got Some(${opt[0]})`);
}

async function assertTraps(fn, msg) {
  let threw = false;
  try {
    await fn();
  } catch (e) {
    threw = true;
  }
  if (!threw) throw new Error(`${msg || 'assertTraps'}: expected a trap but call succeeded`);
}

// ============================================================
// Setup: identity and actor
// ============================================================

global.fetch = fetch;

const privateKeyFile   = fs.readFileSync('./identity.pem');
const privateKeyObject = crypto.createPrivateKey({ key: privateKeyFile, format: 'pem' });
const privateKeyDER    = privateKeyObject.export({ format: 'der', type: 'sec1' });
const PEM_DER_PREFIX   = new Uint8Array([0x30, 0x74, 0x02, 0x01, 0x01, 0x04, 0x20]);
assert(isBufferEqual(PEM_DER_PREFIX, privateKeyDER.slice(0, 7)));

const secret_key    = new Uint8Array(privateKeyDER.slice(7, 7 + 32));
const identity      = Secp256k1KeyIdentity.fromSecretKey(secret_key);
const principal     = identity.getPrincipal();
const principalText = principal.toText();
const principalBytes = principal.toUint8Array();

let localCanisters;
try {
  localCanisters = JSON.parse(fs.readFileSync('../.dfx/local/canister_ids.json'));
} catch (error) {
  console.error('ERROR: no local canister_ids.json. Is dfx running and the canister deployed?');
  process.exit(1);
}

const canisterId = localCanisters['ic-certified-blockchain']['local'];
const url = 'http://localhost:8080';

// Authorise the test identity as Admin
console.log('Authorizing principal:', principalText);
const authorize_cmd = `dfx canister call ic-certified-blockchain authorize '(principal "${principalText}", variant{ Admin })'`;
await exec(authorize_cmd);

// Create agent and await root key before any calls so query verification works
const agent = new HttpAgent({ host: url, identity });
await agent.fetchRootKey();
const actor = Actor.createActor(idlFactory, { agent, canisterId });

// ============================================================
// Phase 1: Initial state
// ============================================================
console.log('\n=== Phase 1: Initial state ===');

await test('first() returns 0 on fresh canister', async () => {
  assertEq(await actor.first(), 0n, 'first()');
});

await test('mid() returns 0 on fresh canister', async () => {
  assertEq(await actor.mid(), 0n, 'mid()');
});

await test('next() returns 0 on fresh canister', async () => {
  assertEq(await actor.next(), 0n, 'next()');
});

await test('last_hash() returns 64-zero hex string on fresh canister', async () => {
  const result = await actor.last_hash();
  assertEq(result, '0'.repeat(64), 'last_hash()');
});

await test('get_certificate() returns None when nothing is staged', async () => {
  assertNone(await actor.get_certificate(), 'get_certificate()');
});

await test('commit() returns None when nothing is staged', async () => {
  // Returns None immediately before inspecting the cert
  assertNone(await actor.commit(new Uint8Array(0)), 'commit() with no staged data');
});

// ============================================================
// Phase 2: Authorization management
// ============================================================
console.log('\n=== Phase 2: Authorization ===');

await test('get_authorized() lists our Admin principal', async () => {
  const auths = await actor.get_authorized();
  const found = auths.find(a => a.id.toText() === principalText);
  if (!found) throw new Error(`${principalText} not in get_authorized()`);
  if (!('Admin' in found.auth)) throw new Error('Expected Admin auth');
});

await test('authorize() adds a User principal', async () => {
  const dummy = Principal.fromText('aaaaa-aa');
  await actor.authorize(dummy, { User: null });
  const auths = await actor.get_authorized();
  const found = auths.find(a => a.id.toText() === 'aaaaa-aa');
  if (!found) throw new Error('User principal not found after authorize');
  if (!('User' in found.auth)) throw new Error('Expected User auth type');
});

await test('deauthorize() removes a principal', async () => {
  const dummy = Principal.fromText('aaaaa-aa');
  await actor.deauthorize(dummy);
  const auths = await actor.get_authorized();
  if (auths.find(a => a.id.toText() === 'aaaaa-aa'))
    throw new Error('Principal still present after deauthorize');
});

await test('authorize() adds an Admin principal', async () => {
  const dummy = Principal.fromText('aaaaa-aa');
  await actor.authorize(dummy, { Admin: null });
  const auths = await actor.get_authorized();
  const found = auths.find(a => a.id.toText() === 'aaaaa-aa');
  if (!found) throw new Error('Admin principal not found after authorize');
  if (!('Admin' in found.auth)) throw new Error('Expected Admin auth type');
  await actor.deauthorize(dummy); // clean up
});

await test('get_authorized() reflects deauthorize cleanup', async () => {
  const auths = await actor.get_authorized();
  if (auths.find(a => a.id.toText() === 'aaaaa-aa'))
    throw new Error('Dummy principal still present after cleanup');
});

// ============================================================
// Phase 3: prepare() → get_certificate() → commit() workflow
// ============================================================
console.log('\n=== Phase 3: Basic block workflow ===');

// Block A: two entries
const data_a0 = new Uint8Array(8); data_a0[7] = 1;
const data_a1 = new Uint8Array(8); data_a1[7] = 2;
let block_a_index;

await test('prepare() returns a non-empty blob', async () => {
  const result = await actor.prepare([data_a0, data_a1]);
  if (result.byteLength === 0) throw new Error('prepare() returned empty blob');
});

await test('prepare() traps if data is already staged', async () => {
  await assertTraps(() => actor.prepare([data_a0]), 'prepare() should trap when already staged');
});

await test('get_certificate() returns Some after prepare()', async () => {
  assertSome(await actor.get_certificate(), 'get_certificate() after prepare');
});

await test('commit() returns block index 0 for first block', async () => {
  const cert = assertSome(await actor.get_certificate(), 'get_certificate');
  const result = await actor.commit(cert);
  block_a_index = assertSome(result, 'commit() result');
  assertEq(block_a_index, 0n, 'First block index');
});

await test('get_certificate() returns None after commit()', async () => {
  assertNone(await actor.get_certificate(), 'get_certificate() after commit');
});

await test('next() returns 1 after first commit', async () => {
  assertEq(await actor.next(), 1n, 'next()');
});

await test('first() stays 0 after first commit', async () => {
  assertEq(await actor.first(), 0n, 'first()');
});

await test('mid() stays 0 after first commit (no secondary)', async () => {
  assertEq(await actor.mid(), 0n, 'mid()');
});

await test('last_hash() is a non-zero 64-char hex string after commit', async () => {
  const h = await actor.last_hash();
  if (h === '0'.repeat(64)) throw new Error('last_hash() is still all zeros');
  if (!/^[0-9a-f]{64}$/i.test(h)) throw new Error(`last_hash() invalid hex: ${h}`);
});

// ============================================================
// Phase 4: Block data integrity
// ============================================================
console.log('\n=== Phase 4: Block data integrity ===');

let block_a;

await test('get_block() returns block with 2 data entries', async () => {
  block_a = await actor.get_block(block_a_index);
  if (block_a.data.length !== 2)
    throw new Error(`Expected 2 entries, got ${block_a.data.length}`);
});

await test('get_block() data[0] matches prepared data', async () => {
  assertBufEq(block_a.data[0], data_a0, 'data[0]');
});

await test('get_block() data[1] matches prepared data', async () => {
  assertBufEq(block_a.data[1], data_a1, 'data[1]');
});

await test('get_block() callers length matches data length', async () => {
  if (block_a.callers.length !== 2)
    throw new Error(`Expected 2 callers, got ${block_a.callers.length}`);
});

await test('get_block() caller[0] is our principal', async () => {
  const c = block_a.callers[0].toText();
  if (c !== principalText)
    throw new Error(`Expected ${principalText}, got ${c}`);
});

await test('get_block() first block has all-zero previous_hash', async () => {
  const ph = new Uint8Array(block_a.previous_hash);
  if (ph.length !== 32) throw new Error(`previous_hash length ${ph.length} != 32`);
  if (!ph.every(b => b === 0)) throw new Error(`First block previous_hash not zero: ${toHex(ph)}`);
});

await test('get_block() has non-empty certificate', async () => {
  if (!block_a.certificate || block_a.certificate.byteLength === 0)
    throw new Error('Block certificate is empty');
});

await test('get_block() has non-empty tree', async () => {
  if (!block_a.tree || block_a.tree.byteLength === 0)
    throw new Error('Block tree is empty');
});

await test('get_block() traps for index before first()', async () => {
  // At this point first()=0, so index must be >= 0; we'll test this after rotation (Phase 9).
  // Here we just confirm a valid index works.
  const b = await actor.get_block(0n);
  assertBufEq(b.data[0], data_a0, 'sanity check get_block(0)');
});

// ============================================================
// Phase 5: Certificate and Merkle tree verification
// ============================================================
console.log('\n=== Phase 5: Certificate and tree verification ===');

let root_key;
let canisterIdPrincipal;

await test('fetch root key from replica via dfx ping', async () => {
  const ping_output = await exec('dfx ping');
  const pos = ping_output.stdout.search('"root_key"');
  if (pos === -1) throw new Error('root_key not found in dfx ping output');
  root_key = new Uint8Array(JSON.parse('{ ' + ping_output.stdout.substring(pos)).root_key);
  canisterIdPrincipal = Principal.fromText(canisterId);
});

await test('block certificate is valid (Certificate.create succeeds)', async () => {
  await Certificate.create({
    certificate: block_a.certificate,
    canisterId,
    rootKey: root_key,
    principal: { canisterId: canisterIdPrincipal },
  });
});

await test('certified_data in certificate matches reconstructed tree hash', async () => {
  const cert = await Certificate.create({
    certificate: block_a.certificate,
    canisterId,
    rootKey: root_key,
    principal: { canisterId: canisterIdPrincipal },
  });
  const certifiedData = cert.lookup_path([
    "canister", canisterIdPrincipal.toUint8Array(), "certified_data",
  ]).value;
  if (!certifiedData) throw new Error('certified_data not found in certificate');
  const block_tree  = Cbor.decode(block_a.tree);
  const reconstructed = await reconstruct(block_tree);
  assertBufEq(certifiedData, reconstructed, 'certifiedData != reconstructed tree hash');
});

await test('certificate contains a valid time', async () => {
  const cert = await Certificate.create({
    certificate: block_a.certificate,
    canisterId,
    rootKey: root_key,
    principal: { canisterId: canisterIdPrincipal },
  });
  const time = cert.lookup_path(["time"]);
  if (!time || !time.value) throw new Error('time not found in certificate');
  const ms = Number(lebDecode(new PipeArrayBuffer(time.value)) / BigInt(1000000));
  if (ms <= 0) throw new Error(`Certificate time is not positive: ${ms}`);
});

await test('entry[0] hash in tree matches computed sha256(sha256(caller)||sha256(data))', async () => {
  const block_tree = Cbor.decode(block_a.tree);
  // Key is the 4-byte BE index of the entry within the block (wasm32: usize = 4 bytes)
  const entry_key  = new Uint8Array([0, 0, 0, 0]);
  const tree_hash  = lookup_path(["certified_blocks", entry_key], block_tree).value;
  if (!tree_hash) throw new Error('Entry 0 not found in tree');
  const expected   = entryHash(principalBytes, data_a0);
  assertBufEq(new Uint8Array(tree_hash), expected, 'entry[0] hash mismatch');
});

await test('entry[1] hash in tree matches computed hash', async () => {
  const block_tree = Cbor.decode(block_a.tree);
  const entry_key  = new Uint8Array([0, 0, 0, 1]);
  const tree_hash  = lookup_path(["certified_blocks", entry_key], block_tree).value;
  if (!tree_hash) throw new Error('Entry 1 not found in tree');
  const expected   = entryHash(principalBytes, data_a1);
  assertBufEq(new Uint8Array(tree_hash), expected, 'entry[1] hash mismatch');
});

await test('previous_hash in tree matches block.previous_hash', async () => {
  const block_tree = Cbor.decode(block_a.tree);
  const key        = new TextEncoder().encode('previous_hash');
  const tree_hash  = lookup_path(["certified_blocks", key], block_tree).value;
  if (!tree_hash) throw new Error('previous_hash not found in tree');
  assertBufEq(new Uint8Array(tree_hash), new Uint8Array(block_a.previous_hash),
    'previous_hash in tree mismatch');
});

// ============================================================
// Phase 6: find()
// ============================================================
console.log('\n=== Phase 6: find() ===');

await test('find() by data[0] hash returns block A index', async () => {
  const h = new Uint8Array(fromHex(sha256(data_a0)));
  const result = assertSome(await actor.find(h), 'find(data_a0 hash)');
  assertEq(result, block_a_index, 'find() block index');
});

await test('find() by data[1] hash returns block A index', async () => {
  const h = new Uint8Array(fromHex(sha256(data_a1)));
  const result = assertSome(await actor.find(h), 'find(data_a1 hash)');
  assertEq(result, block_a_index, 'find() block index for second entry');
});

await test('find() by entry[0] combined hash returns block A index', async () => {
  const combined = entryHash(principalBytes, data_a0);
  const result = assertSome(await actor.find(combined), 'find(combined hash)');
  assertEq(result, block_a_index, 'find() by combined hash');
});

await test('find() returns None for an unknown hash', async () => {
  // sha256 of a sentinel value never stored in the blockchain
  const unknown = new Uint8Array(fromHex(sha256(new Uint8Array([0xde, 0xad, 0xc0, 0xde]))));
  assertNone(await actor.find(unknown), 'find() unknown hash');
});

// ============================================================
// Phase 7: prepare_some() workflow  (block B = two batches)
// ============================================================
console.log('\n=== Phase 7: prepare_some() workflow ===');

const data_b0 = new Uint8Array(8); data_b0[7] = 10;
const data_b1 = new Uint8Array(8); data_b1[7] = 11;
let block_b_index;

await test('prepare_some() returns a non-empty blob for first batch', async () => {
  const result = await actor.prepare_some([data_b0]);
  if (result.byteLength === 0) throw new Error('prepare_some() returned empty blob');
});

await test('prepare_some() returns a non-empty blob for second batch', async () => {
  const result = await actor.prepare_some([data_b1]);
  if (result.byteLength === 0) throw new Error('prepare_some() second call returned empty blob');
});

await test('get_certificate() returns Some after prepare_some()', async () => {
  assertSome(await actor.get_certificate(), 'get_certificate() after prepare_some');
});

await test('commit() succeeds after prepare_some() and returns index 1', async () => {
  const cert = assertSome(await actor.get_certificate(), 'cert');
  const result = await actor.commit(cert);
  block_b_index = assertSome(result, 'commit() after prepare_some');
  assertEq(block_b_index, 1n, 'Block B should be at index 1');
});

await test('block B has both batches of data', async () => {
  const block_b = await actor.get_block(block_b_index);
  if (block_b.data.length !== 2)
    throw new Error(`Expected 2 entries, got ${block_b.data.length}`);
  assertBufEq(block_b.data[0], data_b0, 'block_b data[0]');
  assertBufEq(block_b.data[1], data_b1, 'block_b data[1]');
});

await test('next() returns 2 after second commit', async () => {
  assertEq(await actor.next(), 2n, 'next() after two blocks');
});

await test('block B previous_hash is non-zero (links to block A)', async () => {
  const block_b = await actor.get_block(block_b_index);
  const ph = new Uint8Array(block_b.previous_hash);
  if (ph.every(b => b === 0)) throw new Error('Block B previous_hash is unexpectedly all zero');
});

// ============================================================
// Phase 8: Stale-certificate handling
// ============================================================
console.log('\n=== Phase 8: Stale certificate handling ===');

const data_stale = new Uint8Array([0xde, 0xad]);
const data_extra = new Uint8Array([0xbe, 0xef]);

await test('commit() with stale certificate traps', async () => {
  await actor.prepare([data_stale]);
  const stale_cert = assertSome(await actor.get_certificate(), 'cert before prepare_some');
  // Mutate pending → stale_cert no longer matches the new tree
  await actor.prepare_some([data_extra]);
  await assertTraps(() => actor.commit(stale_cert), 'commit with stale cert should trap');
  // IC rolls back state on trap: pending is still there; commit with fresh cert to clean up
  const fresh_cert = assertSome(await actor.get_certificate(), 'fresh cert after trap');
  const result = await actor.commit(fresh_cert);
  assertSome(result, 'cleanup commit');
});

await test('next() is 3 after stale-cert test block', async () => {
  assertEq(await actor.next(), 3n, 'next()');
});

// ============================================================
// Phase 9: Log rotation
// ============================================================
console.log('\n=== Phase 9: Log rotation ===');

// State: 3 blocks committed (indices 0, 1, 2). No rotation yet.
// Internal: b_is_primary=false, primary=A (len=3), secondary=B (len=0)
// first=0, mid=0, next=3

await test('first() is 0 before any rotation', async () => {
  assertEq(await actor.first(), 0n, 'first()');
});

await test('mid() is 0 before any rotation (secondary is empty)', async () => {
  assertEq(await actor.mid(), 0n, 'mid()');
});

const next_before_first_rotate = await actor.next();

await test('rotate() returns None on first call (secondary was empty, nothing deleted)', async () => {
  assertNone(await actor.rotate(), 'first rotate()');
});

// After first rotate: b_is_primary=true (primary=B empty, secondary=A len=3)
// first=0, mid=0+3=3, next=0+3+0=3

await test('first() unchanged after first rotation', async () => {
  assertEq(await actor.first(), 0n, 'first() after first rotate');
});

await test('mid() equals previous next() after first rotation', async () => {
  assertEq(await actor.mid(), next_before_first_rotate, 'mid() after first rotate');
});

await test('next() equals mid() after first rotation (primary is empty)', async () => {
  assertEq(await actor.next(), await actor.mid(), 'next() == mid() after first rotate');
});

await test('get_block() still works for all secondary blocks after first rotation', async () => {
  const b0 = await actor.get_block(0n);
  assertBufEq(b0.data[0], data_a0, 'secondary block 0 data[0]');
  const b1 = await actor.get_block(1n);
  assertBufEq(b1.data[0], data_b0, 'secondary block 1 data[0]');
});

await test('find() finds entries in secondary after first rotation', async () => {
  const h = new Uint8Array(fromHex(sha256(data_a0)));
  const result = assertSome(await actor.find(h), 'find() in secondary');
  assertEq(result, 0n, 'find() returns correct index');
});

// Add block C to primary (now primary=B)
const data_c0 = new Uint8Array(8); data_c0[7] = 20;
let block_c_index;

await test('can commit a block to primary after first rotation', async () => {
  await actor.prepare([data_c0]);
  const cert = assertSome(await actor.get_certificate(), 'cert');
  const result = await actor.commit(cert);
  block_c_index = assertSome(result, 'commit block C');
  // Block C is at absolute index = first_rotate_next (= 3)
  assertEq(block_c_index, next_before_first_rotate, 'block C index');
});

await test('next() increments after new primary block', async () => {
  assertEq(await actor.next(), next_before_first_rotate + 1n, 'next() after block C');
});

// State: primary=B (len=1, block C), secondary=A (len=3, blocks 0-2)
// first=0, mid=3, next=4

await test('mid() still points to start of primary (unchanged by primary commit)', async () => {
  assertEq(await actor.mid(), next_before_first_rotate, 'mid() after primary commit');
});

await test('second rotate() returns Some (secondary deleted, first advances)', async () => {
  const new_first = assertSome(await actor.rotate(), 'second rotate()');
  assertEq(new_first, next_before_first_rotate, 'new first after second rotate');
});

// After second rotate: secondary (A, len=3) deleted, base_index += 3 → 3
// b_is_primary=false (A is primary=empty, B is secondary=len=1 with block C)
// first=3, mid=3+1=4, next=3+0+1=4

await test('first() advanced to former mid after second rotation', async () => {
  assertEq(await actor.first(), next_before_first_rotate, 'first() after second rotate');
});

await test('next() unchanged after second rotation (same total blocks)', async () => {
  assertEq(await actor.next(), next_before_first_rotate + 1n, 'next() after second rotate');
});

await test('mid() equals next() after second rotation (primary is empty)', async () => {
  assertEq(await actor.mid(), await actor.next(), 'mid() == next() after second rotate');
});

await test('get_block() for block C still works (in secondary after second rotate)', async () => {
  const block_c = await actor.get_block(block_c_index);
  assertBufEq(block_c.data[0], data_c0, 'block C data');
});

await test('get_block() traps for a deleted block (index before first())', async () => {
  await assertTraps(() => actor.get_block(0n), 'get_block(0) on deleted block should trap');
});

await test('find() returns None for entries in deleted secondary', async () => {
  const h = new Uint8Array(fromHex(sha256(data_a0)));
  assertNone(await actor.find(h), 'find() on deleted entry should return None');
});

await test('find() still works for block in remaining secondary', async () => {
  const h = new Uint8Array(fromHex(sha256(data_c0)));
  const result = assertSome(await actor.find(h), 'find() on surviving block');
  assertEq(result, block_c_index, 'find() returns correct index for surviving block');
});

// ============================================================
// Phase 10: Cleanup
// ============================================================
console.log('\n=== Phase 10: Cleanup ===');

await test('deauthorize() removes our test principal', async () => {
  await actor.deauthorize(principal);
  const auths = await actor.get_authorized();
  if (auths.find(a => a.id.toText() === principalText))
    throw new Error('Principal still present after deauthorize');
});

// ============================================================
// Summary
// ============================================================
console.log(`\n${'='.repeat(52)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
if (failed > 0) {
  console.log('TESTS FAILED');
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED');
}

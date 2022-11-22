import fetch from 'node-fetch';
import fs from 'fs';
import crypto from 'crypto';
import sha256 from "sha256";
import { lebDecode, PipeArrayBuffer } from "@dfinity/candid";
import { Principal } from '@dfinity/principal';
import { Secp256k1PublicKey, Secp256k1KeyIdentity } from '@dfinity/identity';
import { Actor, Cbor, Certificate, HttpAgent, lookup_path, reconstruct, hashTreeToString } from '@dfinity/agent';
import { idlFactory } from '../src/declarations/ic-certified-blockchain/ic-certified-blockchain.did.js';
import exec from 'await-exec';
import assert from 'assert';

function toHex(buffer) { // buffer is an ArrayBuffer
	return [...new Uint8Array(buffer)]
		.map(x => x.toString(16).padStart(2, '0'))
		.join('');
}

function fromHex(hex) {
  const hexRe = new RegExp(/^([0-9A-F]{2})*$/i);
  if (!hexRe.test(hex)) {
    throw new Error("Invalid hexadecimal string.");
  }
  const buffer = [...hex]
    .reduce((acc, curr, i) => {
      acc[(i / 2) | 0] = (acc[(i / 2) | 0] || "") + curr;
      return acc;
    }, [])
    .map((x) => Number.parseInt(x, 16));

  return new Uint8Array(buffer).buffer;
}

function isBufferEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  const a8 = new Uint8Array(a);
  const b8 = new Uint8Array(b);
  for (let i = 0; i < a8.length; i++) {
    if (a8[i] !== b8[i]) {
      return false;
    }
  }
  return true;
}

function blockToHex(block) {
  return {
    certificate: toHex(block.certificate),
    tree: toHex(block.tree),
    data: block.data.map((x) => toHex(x)),
    previous_hash: toHex(block.previous_hash)
  };
}

// Install the global brower compatible fetch.
global.fetch = fetch;

// Obtain controller identity.
const privateKeyFile = fs.readFileSync('./identity.pem')
const privateKeyObject = crypto.createPrivateKey({
    key: privateKeyFile,
    format: 'pem'
})
const privateKeyDER = privateKeyObject.export({
    format: 'der',
    type: 'sec1',
});
const PEM_DER_PREFIX = new Uint8Array([0x30, 0x74, 0x02, 0x01, 0x01, 0x04, 0x20]);
assert(isBufferEqual(PEM_DER_PREFIX, privateKeyDER.slice(0, 7)));
let secret_key = new Uint8Array(privateKeyDER.slice(7, 7+32));
const identity = Secp256k1KeyIdentity.fromSecretKey(secret_key);
const principal = identity.getPrincipal().toText();

// Authorize this identity.
console.log('authorizing principal', principal);
let authorize_cmd = 'dfx canister call  ic-certified-blockchain authorize \'(principal "' + principal + '")\'';
console.log('exec:', authorize_cmd, await exec(authorize_cmd));

// Get canister id.
let localCanisters;
try {
  localCanisters = JSON.parse(fs.readFileSync('../.dfx/local/canister_ids.json'));
} catch (error) {
  console.log('No local canister_ids.json found. Continuing production', error);
}
 
const canisterId = localCanisters['ic-certified-blockchain']['local'];
const url = 'http://' + canisterId + '.localhost:8080';

export const createActor = (idlFactory, canisterId, options) => {
  let agentOptions = options ? {...options.agentOptions} : {};
  const agent = new HttpAgent(agentOptions);
	agent.fetchRootKey().catch(err => {
		console.warn('Unable to fetch root key. Check to ensure that your local replica is running');
		console.error(err);
	});
  return Actor.createActor(idlFactory, {
    agent,
    canisterId,
    ...(options ? options.actorOptions : {}),
  });
};

// Now for the actual test
let actor = createActor(idlFactory, canisterId, { agentOptions: { host: url, identity }});

let blocka_0 = new Uint8Array(8);
blocka_0[7] = 1;

let blocka = [blocka_0];
console.log('block a', [toHex(blocka_0)]);

console.log('prepare block a');
let certified_data = await actor.prepare(blocka);
console.log('block a certified data', toHex(certified_data));

console.log('get certificate');
let certificate = await actor.get_certificate();
console.log('block a certificate', toHex(certificate[0]));

let result = await actor.append(certificate[0]);
console.log('append block a', result);
let index = result[0];

console.log('blockchain length', await actor.length());

let block = await actor.get_block(index);
console.log('get block a from index', index, blockToHex(block));

let blocka_0_hash = new Uint8Array(fromHex(sha256(blocka_0)));
console.log('hash of block a entry 0', toHex(blocka_0_hash));
console.log('find block a entry 0', await actor.find(blocka_0_hash));

console.log('dfx ping');
let ping_output = await exec('dfx ping');
let root_key_pos = ping_output.stdout.search('"root_key"');
let root_key = JSON.parse('{ ' + ping_output.stdout.substring(root_key_pos));
root_key = new Uint8Array(root_key.root_key);
console.log('root_key', toHex(root_key));
let block_certificate = Cbor.decode(block.certificate);
// Too verbose
// console.log('block_certificate', { tree: hashTreeToString(block_certificate.tree), signature: toHex(block_certificate.signature)});
let canisterIdPrincipal = Principal.fromText(canisterId);
const cert = await Certificate.create({
  certificate: block.certificate,
  canisterId,
  rootKey: root_key,
});
const certifiedData = cert.lookup([
  "canister", canisterIdPrincipal.toUint8Array(), "certified_data"]);
console.log('certifiedData', toHex(certifiedData));

const time = cert.lookup(["time"]);
console.log('certificate time', new Date(Number(lebDecode(new PipeArrayBuffer(time)) / BigInt(1000000))));

let block_tree = Cbor.decode(block.tree);
let reconstructed = await reconstruct(block_tree);
console.log('reconstructed tree hash', toHex(reconstructed));

assert(isBufferEqual(certifiedData, reconstructed));
console.log('certifiedData == reconstructed tree hash');

console.log('block_tree', hashTreeToString(block_tree));
let block_index = new Uint8Array([0, 0, 0, 0]);
console.log('block_index', toHex(block_index));
const certified_blocka_0_hash = lookup_path(["certified_blocks", block_index], block_tree);
console.log('certified_blocka_0_hash', toHex(new Uint8Array(certified_blocka_0_hash)));
console.log('blocka_0_hash', toHex(blocka_0_hash));
assert(isBufferEqual(new Uint8Array(certified_blocka_0_hash), blocka_0_hash));
console.log('certified_blocka_0_hash == blocka_0_hash');

let blockb_0 = new Uint8Array(8);
blocka_0[7] = 2;

let blockb = [blockb_0];
console.log('block a', [toHex(blocka_0)]);

console.log('prepare_some block b 0');
certified_data = await actor.prepare_some(blockb);
console.log('block b 0 certified data', toHex(certified_data));

let blockb_1 = new Uint8Array(8);
blockb_1[7] = 3;
blockb = [blockb_0];

console.log('prepare_some block b 1');
certified_data = await actor.prepare_some(blockb);
console.log('block b 1 certified data', toHex(certified_data));

console.log('get certificate');
certificate = await actor.get_certificate();
console.log('block a certificate', toHex(certificate[0]));

result = await actor.append(certificate[0]);
console.log('append block b', result);
index = result[0];

console.log('blockchain length', await actor.length());

console.log('deauthorizing', identity.getPrincipal().toText());
await actor.deauthorize(identity.getPrincipal());

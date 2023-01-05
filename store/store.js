import fetch from 'node-fetch';
import fs from 'fs';
import crypto from 'crypto';
import sha256 from "sha256";
import { Principal } from '@dfinity/principal';
import { Secp256k1KeyIdentity } from '@dfinity/identity';
import { Actor, Cbor, Certificate, HttpAgent } from '@dfinity/agent';
import { idlFactory } from '../src/declarations/ic-certified-blockchain/ic-certified-blockchain.did.js';

// Install the global brower compatible fetch.
global.fetch = fetch;

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

if (process.argv.length < 7) {
  console.log("Usage: node store.js <identity> <canisterId> <networkURL> <productionBool> <datafile> [<datafile>]...");
  console.log("Example: node store.js ./identity.pem ryjl3-tyaaa-aaaaa-aaaba-cai https://ic0.app true ./entry1 ./entry2 ./entry3");
  process.exit(1);
}
const identity_path = process.argv[2];
const canisterId = process.argv[3];
const network = process.argv[4];
const production = process.argv[5] == 'true';
const entries = process.argv.slice(6);

// Obtain controller identity.
const privateKeyFile = fs.readFileSync(identity_path);
const privateKeyObject = crypto.createPrivateKey({
    key: privateKeyFile,
    format: 'pem'
});
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
let authorize_cmd = 'dfx canister call ic-certified-blockchain authorize \'(principal "' + principal + '")\'';
console.log('To authorize the identity principal run:', authorize_cmd);

const canisterPosition = network.search("//") + 2;
const url = network.substring(0, canisterPosition) + canisterId + '.' + network.substring(canisterPosition);

export const createActor = (idlFactory, canisterId, options) => {
  let agentOptions = options ? {...options.agentOptions} : {};
  const agent = new HttpAgent(agentOptions);
  if (!production) {
    console.log('Fetching root key.');
    agent.fetchRootKey().catch(err => {
      console.warn('ERROR: unable to fetch root key. Check to ensure that your local replica is running');
      console.error(err);
    });
  }
  return Actor.createActor(idlFactory, {
    agent,
    canisterId,
    ...(options ? options.actorOptions : {}),
  });
};

// Now for the actual test
let actor = createActor(idlFactory, canisterId, { agentOptions: { host: url, identity }});

let data = [];
let hashes = [];
// Check to see if the entries already exist.
for (var entry of entries) {
  console.log('loading entry from file', entry);
  const entryData = new Uint8Array(fs.readFileSync(entry));
  data.push(entryData);
  let hash = new Uint8Array(fromHex(sha256(entryData)));
  hashes.push(hash);
  let index = await actor.find(hash);
  if (index.length > 0) {
    console.error('ERROR: entry', entry, 'found with hash', toHex(hash), 'at block', index[0]);
    process.exit(1);
  }
}

let pre_unprepare = await actor.unprepare();
if (pre_unprepare.length > 0) {
  console.error('ERROR: outstanding block of length', pre_unprepare.length);
  const randomName = Math.random().toString(36).substring(2, 15) + Math.random().toString(23).substring(2, 5);
  for (var i in pre_unprepare) {
    const filename = 'block_entry_' + randomName + '.' + i.toString();
    console.error('saving entry', i, 'to file', filename);
    fs.writeFileSync(filename, pre_unprepare[i], 'binary');
  }
  process.exit(1);
}

let certified_data = await actor.prepare(data);
console.log('prepare() => certified data', toHex(certified_data));
let certificate = await actor.get_certificate();
if (certificate.length < 1) {
  console.error('ERROR: get_certificate() failed');
  process.exit(1);
}
console.log('get_certificate() => certificate', toHex(certificate[0]));
let index = await actor.commit(certificate[0]);
if (index.length < 1) {
  console.error('ERROR: commit() failed');
  process.exit(1);
}
console.log('SUCCESS! new block', index[0], 'new blockchain length', await actor.length());

import { Principal } from '@dfinity/principal';
import { Cbor, Certificate, lookup_path, reconstruct, hashTreeToString } from '@dfinity/agent';

const IC_ROOT_KEY = new Uint8Array([48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 129, 76, 14, 110, 199, 31, 171, 88, 59, 8, 189, 129, 55, 60, 37, 92, 60, 55, 27, 46, 132, 134, 60, 152, 164, 241, 224, 139, 116, 35, 93, 20, 251, 93, 156, 12, 213, 70, 217, 104, 95, 145, 58, 12, 11, 44, 197, 52, 21, 131, 191, 75, 67, 146, 228, 103, 219, 150, 214, 91, 155, 180, 203, 113, 113, 18, 248, 71, 46, 13, 90, 77, 20, 80, 95, 253, 116, 132, 176, 18, 145, 9, 28, 95, 135, 185, 136, 131, 70, 63, 152, 9, 26, 11, 170, 174]);

function toHex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
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

function toBEBytesUint32 (num) {
  return new Uint8Array([
    (num & 0xff000000) >> 24,
    (num & 0x00ff0000) >> 16,
    (num & 0x0000ff00) >> 8,
    (num & 0x000000ff)
  ]);
}

export async function getCertificateDate(block, canisterId) {
  let canisterIdPrincipal = Principal.fromText(canisterId);
  const cert = await Certificate.create({
      certificate: block.certificate,
      canisterId,
      rootKey: root_key,
  });
  const time = cert.lookup(["time"]);
  return new Date(Number(lebDecode(new PipeArrayBuffer(time)) / BigInt(1000000)));
}

export function getBlockEntryIndex(block, entry) {
  for (var i in block.data) {
    if (isBufferEqual(entry, block.data[i])) {
      return i;
    }
  }
  return -1;
}

export async function verifyIcCertifiedBlockChainEntry(block, entry_index, canisterId, rootKey = IC_ROOT_KEY) {
  let entry = block.data[entry_index];
  let caller = block.callers[entry_index];
  entry_index = toBEBytesUint32(entry_index);
  const canisterIdPrincipal = Principal.fromText(canisterId);
  try {
    const cert = await Certificate.create({
      certificate: block.certificate,
      canisterId,
      rootKey: root_key,
    });
  } catch (error) {
    console.log('Certificate verification failed', error);
    return false;
  }
  const certifiedData = cert.lookup([
    "canister", canisterIdPrincipal.toUint8Array(), "certified_data"]);
  const block_tree = Cbor.decode(block.tree);
  const reconstructed = await reconstruct(block_tree);

  if (!isBufferEqual(certifiedData, reconstructed)) {
    console.log('CertifiedData does not match tree hash');
    return false;
  }
  const certified_entry_hash = lookup_path(["certified_blocks", entry_index], block_tree);
  const entry_hash = new Uint8Array(fromHex(sha256(sha256(caller) + sha256(entry))));
  if (!isBufferEqual(new Uint8Array(certified_entry_hash), entry_hash)) {
    console.log('Certified block entry hash does not match block entry hash');
    return false;
  }
  return true;
}

// Returns null or [block_index, entry_index, date].
export async function getAndVerifyCertifiedBlockChainEntry(entry, canisterId) {
  const agent = new HttpAgent();
  const actor = Actor.createActor(idlFactory, { agent, canisterId });
  let hash = new Uint8Array(fromHex(sha256(entry)));
  let block_index = actor.find(hash);
  if (block_index.length < 1) {
    return undefined;
  }
  block_index = block_index[0];
  let block = await actor.get_block(block_index[0]);
  let entry_index = getBlockEntryIndex(block, entry);
  if (entry_index < 0) {
    return undefined;
  }
  if (!await verifyIcCertifiedBlockChainEntry(block, entry_index, canisterId)) {
    return undefined;
  }
  return [block_index, entry_index, await getCertifiedDate(block, canisterId)];
}

export function printBlock(block) {
  let block_certificate = Cbor.decode(block.certificate);
  console.log('certificate tree', hashTreeToString(block_certificate.tree));
  console.log('certificate signature', toHash(block_certificate.signature));
  console.log('block tree', hashTreeToString(block.tree));
  console.log('data', block.data.map((x) => toHex(x)));
  console.log('callers', block.callers.map((x) => toHex(x)));
  console.log('preivous_hash', toHex(block.previousHash));
}

export async function getAndPrintBlockContainingEntry(entry, canisterId) {
  const agent = new HttpAgent();
  const actor = Actor.createActor(idlFactory, { agent, canisterId });
  let hash = new Uint8Array(fromHex(sha256(entry)));
  let block_index = actor.find(hash);
  if (block_index.length < 1) {
    return undefined;
  }
  block_index = block_index[0];
  let block = await actor.get_block(block_index[0]);
  printBlock(block);
}

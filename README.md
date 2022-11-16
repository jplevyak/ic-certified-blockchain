# A Certified Blockchain

This canister holds a chain of blocks, each of which is certified by the IC Root Key and contain both a certification time and a hash of previous blocks.

The result is a irrefutable record independent of the controllers.  The certified blockchain can be made publically available for remote backup.  The canister can also owned by a detached canister e.g. https://github.com/ninegua/ic-blackhole or a DOA to ensure availability.

## Blockchain

The blockchain is a sequence of blocks of the format:

```
type Block = record {
  // Certificate is signed by the NNS root key and contains the root of tree.
  certificate: blob;
  // Under b"certified_blocks is a map from i as u32 BE bytes to sha256(data[i]).
  tree: blob;
  // The raw data entries.
  data: vec blob;
  previous_hash: blob;
};
```

The canister smart contract provides an API to store, find entries and retrieve blocks:

```
service blockchain: {
  // Stage a block, returning the the data to be certified for informational purposes.
  prepare: (data: vec blob) -> (blob);
  // Clear and return nay staged data.
  unprepare: () -> (vec blob);
  // Get certificate for the certified data.
  get_certificate: () -> (opt blob) query;
  // Append the staged data with certificate and tree.
  append: (certificate: blob) -> (opt nat64);
  // Get a certified block.
  get_block: (index: nat64) -> (Block) query;
  // Find block index with matching block hash or latest matching data hash.
  find: (hash: blob) -> (opt nat64) query;
  // Return the number of blocks stored.
  length: () -> (nat64) query;
  authorize: (principal) -> ();
  deauthorize: (principal) -> ();
  get_authorized: () -> (vec principal) query;
}
```

## Certification

The certificate constains an NNS signed delegation for the canister to the subnet which certifies the canister root hash along with the date.  The canister root hash is the root of the Merkle tree containing the hashes of all the block entries.  This enables each entry to be independently certified by extracting the corresponding path from the tree.  Code to verify blocks is found in the `./verify` directory.

## Storing Blocks

A block is an array of byte arrays (entries).  First the block is staged by calling `prepare()` which returns the tree root hash (for reference).  Then the certificate is retrieved via `get_certificate()` and then the block is appended by calling `append()` with the certificate.  Code to upload blocks is found in the `./store` directory.

## Blockchain Persistence

The canister smart contract stores all persistent data in stable memory.  There is no provision for deleting or rewriting blocks short of reinstalling or deleting the canister.  However, because the blocks are certified, they can be backed up remotely and validated offline.  The blocks can even be transfered to a different canister smart contract by re-storing the blocks and substituting the original certificate during the `append()` phase.

## Development

### Depenedencies

* node, npm
* rustup, cargo, rustc with wasm

### Setup

* (cd tests; npm i)

### Build

* make build

### Test

* dfx start --background
* dfx deploy
* make test

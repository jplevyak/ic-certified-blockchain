# A Certified Blockchain

This canister holds a chain of blocks, each of which is certified by the IC Root Key and contain both a certification time and a hash of previous blocks.

The result is a irrefutable record independent of the controllers.  The certified blockchain is public and available for remote backup.  The canister can also owned by a detached canister e.g. https://github.com/ninegua/ic-blackhole or a DAO to ensure availability.

## Blockchain

The blockchain is a sequence of blocks of the format:

```
type Block = record {
  // Certificate is signed by the NNS root key and contains the root of tree.
  certificate: blob;
  // Under label "certified_blocks" is a map from i as u32 BE bytes to sha256(data[i]).
  tree: blob;
  // The raw data entries.
  data: vec blob;
  previous_hash: blob;
};
```

The canister smart contract provides an API to store, find entries and retrieve blocks:

```
type Auth = variant { User; Admin };
type Authorization = record {
  id: principal;
  auth: Auth;
};

service blockchain: (opt text) -> {
  // Stage a block, returning the certified data for informational purposes.
  // Traps if some data is already staged.
  prepare: (data: vec blob) -> (blob);
  // Stage some (more) data into a block, returning the certified data for informational purposes.
  prepare_some: (data: vec blob) -> (blob);
  // Get certificate for the certified data. Returns None if nothing is staged.
  get_certificate: () -> (opt blob) query;
  // Append the staged data with certificate and tree.  Traps if the certificate is stale.
  // Returns None if there is nothing staged.
  append: (certificate: blob) -> (opt nat64);
  // Get a certified block.
  get_block: (index: nat64) -> (Block) query;
  // Find block index with matching block hash or latest matching data hash.
  find: (hash: blob) -> (opt nat64) query;
  // Return the number of blocks stored.
  length: () -> (nat64) query;
  // Return hex string representing the hash of the last block or 0.
  last_hash: () -> (text) query;
  // Manage the set of Principals allowed to prepare and append (user) or authorize (admin).
  authorize: (principal, Auth) -> ();
  deauthorize: (principal) -> ();
  get_authorized: () -> (vec Authorization) query;
}
```

## Certification

The certificate contains an NNS signed delegation for the canister to the subnet which certifies the canister root hash along with the date.  The canister root hash is the root of the Merkle tree containing the hashes of all the block entries.  This enables each entry to be independently certified by extracting the corresponding path from the tree.  Code to verify blocks is found in the `./verify` directory.

Additional verifications e.g. the signature of the appender should be verified at the application level.

## Storing Blocks

A block is an array of byte arrays (entries).  First the block is staged by calling `prepare()` which returns the tree root hash (for reference).  Then the certificate is retrieved via `get_certificate()` and then the block is appended by calling `append()` with the certificate.  Code to upload blocks is found in the `./store` directory.

## Blockchain Persistence

The canister smart contract stores all persistent data in stable memory.  There is no provision for deleting or rewriting blocks short of reinstalling or deleting the canister.  However, because the blocks are certified, they can be backed up remotely and validated offline.  The blocks can even be transfered to a different canister smart contract by re-storing the blocks and substituting the original certificate during the `append()` phase.

## Usage

### Single Writer

A single writer should use `prepare()` then `get_certificate()` then `append()`.  An error in `prepare()` means that there is already a prepared block which needs `get_certificate()` then `append()`.  An error in `get_certificate()` or `append()` mean that there is no prepared block or that the certificate is stale.  The client should use `get_block()` to determine if the data has already been written and retry if not. 

### Multiple Writer

Multiple writers can either use the single writer workflow or they can all call `prepare_some()` and then `get_certificate()` followed by `append()` recognizing that the `get_certificate()` `append()` commit sequence might fail if there is a race.  Use of `prepare_some()` may result in higher throughput.  Clients may defer or retry the commit sequence until `get_certificate()` returns None.  Note that there is no provision in this code for DOS prevention e.g. logging callers of `prepare_some()` which may be advisable in some use cases.

### Backup and Remove Old Blocks

In some use cases it may be desirable to backup and remove old blocks from the canister smart contract.  A controller principal with `admin` authoriation should remove all user permissions to prevent updates to the blockchain, `get_block` all the blocks and back them up, then deploy with `mode=reinstall` to wipe stable memory and (optionally) pass in the final block's hash (the result of `last_hash()`) as a 64-character hex value: `dfx deploy --argument '(opt "AABB...")'`.

## Development

### Depenedencies

* node, npm
* rustup, cargo, rustc with wasm
* hash\_tree.rs is copied from github.com/dfinity/agent-rssrc/hash\_tree/mod.rs

### Setup

* (cd tests; npm i)

### Build

* make build

### Test

* dfx start --background
* dfx deploy
* make test

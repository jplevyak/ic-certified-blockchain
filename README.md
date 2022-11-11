# A Certified Blockchain

This canister holds a chain of blocks, each of which is certified by the IC Root Key and contain both a certification time and a hash of previous blocks.

The result is a irrefutable record independent of the controllers.  The certified blockchain can be made publically available for remote backup.  The canister can also owned by a detached canister e.g. https://github.com/ninegua/ic-blackhole or a DOA to ensure availability.

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

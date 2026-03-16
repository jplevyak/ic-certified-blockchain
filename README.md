# A Certified Blockchain

This canister holds a chain of blocks, each of which is certified by the IC Root Key and contain both a certification time and a hash of previous blocks.

The result is a irrefutable record independent of the controllers.  The certified blockchain is public and available for remote backup.  The canister can also owned by a detached canister e.g. https://github.com/ninegua/ic-blackhole or a DAO to ensure availability.

## Blockchain

The blockchain is a sequence of blocks of the format:

```
type Block = record {
  // Certificate is signed by the NNS root key and contains the root of tree.
  certificate: blob;
  // Under b"certified_blocks is a map from i as u32 BE bytes to sha256(sha256(caller{i])sha256(data[i]))
  // with an entry from "previous_hash" to previous_hash.
  tree: blob;
  // The raw data entries.
  data: vec blob;
  // Callers of prepare()/prepare_some() for corresponding "data".
  callers: vec principal;
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
  // Stage some (more) data into a block, returning the hash of the root of tree for informational purposes.
  prepare_some: (data: vec blob) -> (blob);
  // Get certificate for the certified data. Returns None if nothing is staged.
  get_certificate: () -> (opt blob) query;
  // Append the staged data with certificate and tree.  Traps if the certificate is stale.
  // Returns None if there is nothing staged.
  commit: (certificate: blob) -> (opt nat64);
  // Get a certified block.
  get_block: (index: nat64) -> (Block) query;
  // Find block index with matching block hash or latest matching data entry hash.
  find: (hash: blob) -> (opt nat64) query;
  // Return the index of the first block stored.
  first: () -> (nat64) query;
  // Return the index of the start of the primary part (length of log - first() - secondary.len()).
  mid: () -> (nat64) query;
  // Return the index of the next block to be stored (the length of the log - first()).
  next: () -> (nat64) query;
  // Return hex string representing the hash of the last block or 0.
  last_hash: () -> (text) query;
  // Rotate the log by making the primary part secondary and deleting the old secondary and making it primary.
  // Returns the new first index stored if the secondary part had anything to delete.
  rotate: () -> (opt nat64);
  // Manage the set of Principals allowed to prepare and append (User) or authorize (Admin).
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

The canister smart contract stores all persistent data in stable memory.  There is no provision for deleting or rewriting blocks short of reinstalling or deleting the canister.  However, because the blocks are certified, they can be backed up remotely and validated offline.  The blocks can even be transferred to a different canister smart contract by re-storing the blocks and substituting the original certificate during the `append()` phase.

## Usage

### Single Writer

A single writer should use `prepare()` then `get_certificate()` then `append()`.  An error in `prepare()` means that there is already a prepared block which needs `get_certificate()` then `append()`.  An error in `get_certificate()` or `append()` mean that there is no prepared block or that the certificate is stale.  The client should use `get_block()` to determine if the data has already been written and retry if not.

### Multiple Writer

Multiple writers can either use the single writer workflow or they can all call `prepare_some()` and then `get_certificate()` followed by `append()` recognizing that the `get_certificate()` `append()` commit sequence might fail if there is a race.  Use of `prepare_some()` may result in higher throughput.  Clients may defer or retry the commit sequence until `get_certificate()` returns None.  Note that there is no provision in this code for DOS prevention although callers of `prepare_some()` are recorded which may be of some use.

### Log Rotation

In some use cases it may be desirable to backup and remove old blocks from the canister smart contract. Since the committed log entries are individually certified, they can be verified independent of the smart contract so the backup can be used as a primary source. Safe backup and clearing of old log entries is done via a process of log rotation. Internally the blockchain log is broken up into a primary part and a secondary part.  Periodically a backup agent should `get_block()` all blocks between `first()` and `mid()` (the first index beyond the secondary part) then call `rotate()` which makes the primary secondary, deletes the data in the old secondary and makes it primary. Note that log indexes are preserved (do not change) over time and that `find()` continues to work for entries in both the primary and secondary parts of the log.

## CLI

The `cli/` directory contains `icb`, a Node.js command-line tool that covers the full canister API.

### Setup

```
(cd cli; npm install)        # or: make cli
cp cli/.env.example cli/.env
# edit cli/.env to set your identity and canister ID
```

### Configuration

All settings can be placed in `cli/.env` (relative paths are resolved from the `cli/` directory) or passed as global flags:

| Variable | Flag | Default | Description |
|---|---|---|---|
| `IC_NETWORK` | `--network <url>` | `http://localhost:8080` | Replica or boundary-node URL |
| `IC_IDENTITY_FILE` | `--identity <file>` | — | Path to a secp256k1 PEM file (`dfx identity export <name>`) |
| `IC_CANISTER_ID` | `--canister <id>` | auto-detected | Canister ID; auto-read from `.dfx/local/canister_ids.json` if omitted |
| `IC_PRODUCTION` | `--production` | `false` | Skip `fetchRootKey()` on mainnet |

### Commands

#### `icb status`

Print chain state and the authorized principal list.

```
$ icb status
network    : http://localhost:8080
canister   : uxrrr-q7777-77774-qaaaq-cai
first      : 0
mid        : 10
next       : 12
blocks     : 12
last_hash  : 3a7f…
staged     : no
authorized : 1
  abc12-… [Admin]
```

#### `icb append [entries…] [-f file] [-x hex]`

Safely append a block.  Each positional argument becomes one blob entry (UTF-8 encoded).  Binary entries can be added with `--file` (reads the file) or `--hex` (decodes a hex string).  All options are repeatable and can be combined in one block.

Before staging, any previously staged data is committed first, and concurrent-writer races are handled automatically.

```bash
icb append "log entry text"
icb append "entry one" "entry two"          # two entries in one block
icb append --file audit.bin                  # binary file entry
icb append "label" --file data.bin           # mixed entries in one block
icb append --hex deadbeef                    # raw hex entry
```

#### `icb get <index> [--verify] [--verbose] [--raw]`

Display a block.  Text entries are printed as strings; binary entries are shown as hex.

* `--verify` — verify the IC certificate, Merkle tree, and entry hashes
* `--verbose` — also print per-entry sha256 and certificate/tree excerpts
* `--raw` — output raw JSON (snapshot format)

```
$ icb get 5 --verify
Block #5  [2 entries]
  previous_hash : a1b2c3…
  entry[0]
    caller : abc12-…
    data   : "hello world"
  entry[1]
    caller : abc12-…
    data   : <256 bytes 0xdeadbeef…>
Verifying… OK
```

#### `icb find <query> [-f] [-x] [-v]`

Find which block contains a given data entry by hashing the query and calling `find()`.

* Default: sha256 of the query text
* `-f` / `--file`: sha256 of the file at the given path
* `-x` / `--hex`: treat the query as a raw 32-byte hex hash (no sha256 applied)
* `-v` / `--verbose`: print the full block after finding it

```bash
icb find "hello world"
icb find --file audit.bin
icb find --hex a9a66794…
```

#### `icb download [-s N] [-e N] [-o dir]`

Download a range of blocks to individual JSON files (`block-<index>.json`) in a directory.

```bash
icb download                         # all current blocks → ./blocks/
icb download --start 10 --end 19 --output ./archive/
```

#### `icb snapshot [-s N] [-e N] [-o file]`

Download a range of blocks (default: all) into a single self-contained JSON file that includes the canister ID and root key, making it suitable for offline verification.

```bash
icb snapshot                         # → blockchain-<timestamp>.json
icb snapshot --output backup.json
icb snapshot --start 0 --end 99 --output segment.json
```

Snapshot format:

```json
{
  "version": 1,
  "canisterId": "uxrrr-q7777-77774-qaaaq-cai",
  "rootKey": "<hex>",
  "network": "http://localhost:8080",
  "createdAt": "2026-03-16T19:00:00.000Z",
  "first": 0,
  "next": 100,
  "blocks": [
    {
      "index": 0,
      "certificate": "<hex>",
      "tree": "<hex>",
      "data": ["<hex>", "…"],
      "callers": ["<principal>", "…"],
      "previous_hash": "<hex>"
    }
  ]
}
```

#### `icb verify [path] [-s N] [-e N] [--no-chain] [--root-key <hex>]`

Verify blockchain integrity.  `<path>` can be:

| `<path>` | Source |
|---|---|
| *(omitted)* | Live chain — fetches blocks directly from the canister |
| `backup.json` | Snapshot file produced by `icb snapshot` — fully offline, root key embedded |
| `block-5.json` | Single block file produced by `icb download` |
| `./blocks/` | Directory of `block-*.json` files produced by `icb download` |

For each block, the following are checked:

1. IC certificate signature (BLS over the subnet delegation chain)
2. Reconstructed Merkle tree hash matches `certified_data` in the certificate
3. Each entry's `sha256(sha256(caller) ‖ sha256(data))` matches the certified tree
4. `previous_hash` field matches the certified value in the tree
5. Hash chain continuity: `block[i].previous_hash == sha256(candid_encode(block[i-1]))` — rotation boundaries (all-zero `previous_hash`) are noted, not flagged as errors

When verifying a single block file or a directory, the root key must be available.  It is fetched from the live network automatically unless `--root-key` is given.  The canister ID is resolved from the global `--canister` flag or auto-detected.

```bash
icb verify                              # live chain
icb verify backup.json                  # offline snapshot (root key embedded)
icb verify backup.json --start 50       # partial range from snapshot
icb verify ./blocks/                    # directory of downloaded blocks
icb verify block-5.json                 # single downloaded block
icb verify ./blocks/ --root-key 3081…  # fully offline, root key explicit
icb verify --no-chain                   # skip hash-chain re-derivation
```

#### `icb rotate`

Rotate the log: the current primary segment becomes secondary and the secondary (if any) is deleted.  Prints the before/after `first`/`mid`/`next` indices.

A safe rotation workflow is:

```bash
icb snapshot --end $(icb status | grep ^mid | awk '{print $3-1}')
icb rotate
```

#### `icb auth list`

List all authorized principals and their roles (`User` or `Admin`).

#### `icb auth add <principal> [--admin]`

Authorize a principal.  Default role is `User`; pass `--admin` for `Admin`.  Requires the calling identity to be an `Admin`.

```bash
icb auth add abc12-… --admin
```

#### `icb auth remove <principal>`

Deauthorize a principal.  Requires `Admin`.

### Global flags

All commands accept these flags, which override `.env`:

```
--network <url>    IC network URL
--identity <file>  Identity PEM file (secp256k1)
--canister <id>    Canister ID
--production       Use mainnet root key; skip fetchRootKey()
```

## Development

### Dependencies

* node, npm
* rustup, cargo, rustc with wasm
* hash\_tree.rs is copied from github.com/dfinity/agent-rs/src/hash\_tree/mod.rs

### Setup

```
(cd cli; npm install)
(cd tests; npm install)
```

### Build

* `make build` — compile the Rust canister
* `make cli` — install CLI dependencies

### Test

```
make test-clean    # stop → clean start → deploy → run tests
make test          # run tests against the already-running canister
```

all:: build cli test

build:
	RUSTFLAGS='-C target-feature=+bulk-memory' cargo build --release --target wasm32-unknown-unknown

cli:
	(cd cli; npm install)

redeploy: build
	RUSTFLAGS='-C target-feature=+bulk-memory' dfx deploy --mode=reinstall ic-certified-blockchain -y

restart:
	-dfx stop
	dfx start --clean --background
	RUSTFLAGS='-C target-feature=+bulk-memory' dfx deploy --all

store:
	dfx canister call  ic-certified-blockchain authorize '(principal "vkgr6-2tybk-buvwc-vwohz-6muzj-5mqpb-ul5bi-ewcq5-47dxq-aq55y-uae", variant{ Admin })'
	node store/store.js test/identity.pem $(dfx canister id ic-certified-blockchain) http://127.0.0.1:8080 false store.dat

test:
	(cd tests; node test.js)

test-clean:
	bash test.sh

.PHONY: all build cli redeploy restart store test test-clean

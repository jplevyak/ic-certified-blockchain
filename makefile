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
	RUSTFLAGS='-C target-feature=+bulk-memory' dfx deploy
	dfx canister call ic-certified-blockchain authorize '(principal "vkgr6-2tybk-buvwc-vwohz-6muzj-5mqpb-ul5bi-ewcq5-47dxq-aq55y-uae", variant{ Admin})'

test:
	(cd tests; node test.js)

test-clean:
	bash test.sh

.PHONY: all build cli redeploy restart test test-clean

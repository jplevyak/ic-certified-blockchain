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

test:
	(cd tests; node test.js)

test-clean:
	bash test.sh

.PHONY: all build cli redeploy restart test test-clean

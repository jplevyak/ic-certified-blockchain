all:: build test

build:
	RUSTFLAGS='-C target-feature=+bulk-memory' cargo build --release --target wasm32-unknown-unknown

redeploy: build
	RUSTFLAGS='-C target-feature=+bulk-memory' dfx deploy --mode=reinstall ic-certified-blockchain -y 

test:
	(cd tests; node tests.js)

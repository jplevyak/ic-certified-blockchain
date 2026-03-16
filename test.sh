#!/usr/bin/env bash
set -euo pipefail

DEPLOY_TIMEOUT=${DEPLOY_TIMEOUT:-180}
TEST_TIMEOUT=${TEST_TIMEOUT:-120}

# Stop any running dfx instance
echo "==> Stopping dfx..."
dfx stop 2>/dev/null || true

# Start fresh with a clean replica
echo "==> Starting dfx (clean)..."
dfx start --clean --background

# Wait for replica to be healthy
echo "==> Waiting for replica..."
for i in $(seq 1 20); do
  dfx ping 2>/dev/null && break || sleep 1
done

# Build and deploy
echo "==> Deploying canister (timeout ${DEPLOY_TIMEOUT}s)..."
timeout "${DEPLOY_TIMEOUT}" sh -c 'RUSTFLAGS="-C target-feature=+bulk-memory" dfx deploy'

# Run tests
echo "==> Running tests (timeout ${TEST_TIMEOUT}s)..."
cd tests
timeout "${TEST_TIMEOUT}" node test.js

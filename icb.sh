#!/usr/bin/env bash
# icb — shell wrapper for the ic-certified-blockchain CLI
# Runs cli/cli.js via Node from any working directory.
# Usage: ./icb.sh [global options] <command> [options] [args]
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$DIR/cli/cli.js" "$@"

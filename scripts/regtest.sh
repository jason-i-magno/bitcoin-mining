#!/usr/bin/env bash
# Run a private regtest bitcoind whose data lives in ./data.
#
#   scripts/regtest.sh start          start bitcoind and load (or create) the "miner" wallet
#   scripts/regtest.sh stop           stop bitcoind
#   scripts/regtest.sh reset          stop bitcoind and delete the regtest chain and wallet
#   scripts/regtest.sh cli ARGS...    run bitcoin-cli against this node
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATADIR="$ROOT/data"
PIDFILE="$DATADIR/regtest/bitcoind.pid"

cli() { bitcoin-cli -regtest -datadir="$DATADIR" "$@"; }

running() { cli getblockchaininfo >/dev/null 2>&1; }

start() {
  if running; then
    echo "bitcoind is already running"
  else
    mkdir -p "$DATADIR"
    # -fallbackfee lets the wallet send transactions without fee estimates, which regtest lacks.
    bitcoind -regtest -datadir="$DATADIR" -daemonwait -fallbackfee=0.0001
  fi
  if ! cli listwallets 2>/dev/null | grep -q '"miner"'; then
    cli loadwallet miner >/dev/null 2>&1 || cli createwallet miner >/dev/null 2>&1 ||
      echo "warning: wallet unavailable; pass --address to the miner" >&2
  fi
  echo "regtest node running (datadir: $DATADIR, height: $(cli getblockcount))"
}

stop() {
  running || return 0
  cli stop >/dev/null
  # bitcoind removes its pid file once shutdown completes.
  while [[ -f "$PIDFILE" ]]; do sleep 0.2; done
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  reset) stop && rm -rf "$DATADIR/regtest" && echo "regtest chain deleted" ;;
  cli) shift && cli "$@" ;;
  *)
    sed -n '2,8s/^# \{0,1\}//p' "$0" >&2
    exit 1
    ;;
esac

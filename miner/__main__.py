"""Command-line entry point: python3 -m miner --blocks 10"""

import argparse
import sys
import urllib.error
from pathlib import Path

from .mining import mine_block
from .rpc import BitcoinRPC, RPCError

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="python3 -m miner", description="Mine blocks on a local regtest bitcoind.")
    parser.add_argument("-n", "--blocks", type=int, default=1, help="number of blocks to mine (default: 1)")
    parser.add_argument("--address", help="where to pay block rewards (default: a new address from the node's wallet)")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:18443", help="default: %(default)s")
    parser.add_argument(
        "--datadir",
        type=Path,
        default=PROJECT_ROOT / "data",
        help="bitcoind datadir, used to find the RPC cookie (default: ./data)",
    )
    parser.add_argument("--rpc-user", help="use username/password auth instead of the cookie")
    parser.add_argument("--rpc-password", default="")
    return parser.parse_args(argv)


def connect(args) -> BitcoinRPC:
    if args.rpc_user:
        return BitcoinRPC(args.rpc_url, args.rpc_user, args.rpc_password)
    return BitcoinRPC.from_cookie(args.rpc_url, args.datadir / "regtest" / ".cookie")


def payout_script(rpc: BitcoinRPC, address: str | None) -> tuple[str, bytes]:
    if address is None:
        try:
            address = rpc.call("getnewaddress")
        except RPCError as e:
            sys.exit(f"could not get an address from the node's wallet ({e}); pass --address instead")
    info = rpc.call("validateaddress", address)
    if not info["isvalid"]:
        sys.exit(f"not a valid address for this chain: {address}")
    return address, bytes.fromhex(info["scriptPubKey"])


def main(argv=None):
    args = parse_args(argv)
    try:
        rpc = connect(args)
        chain = rpc.call("getblockchaininfo")["chain"]
    except (FileNotFoundError, urllib.error.URLError) as e:
        sys.exit(f"cannot reach bitcoind ({e}). Start it with: scripts/regtest.sh start")

    address, script_pubkey = payout_script(rpc, args.address)
    print(f"Mining {args.blocks} block(s) on {chain}, paying {address}")

    for _ in range(args.blocks):
        block = mine_block(rpc, script_pubkey)
        print(
            f"height {block.height:>6}  {block.hash}  "
            f"nonce={block.nonce} extranonce={block.extranonce} txs={block.tx_count} "
            f"attempts={block.attempts} ({block.seconds:.2f}s)"
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
broadcast-then-broadcast-zmq.py

Broadcast TX1, wait -- event-driven via ZMQ 'hashblock' -- until it is confirmed
in a block on the active chain, then broadcast TX2.

The two raw transactions are OPAQUE hex inputs YOU supply (a hex string or a path
to a file containing hex). This script constructs no transaction contents; it is
generic sequential-broadcast plumbing whose "wait" step is push-driven instead of
polled.

Node requirements (elements.conf / bitcoin.conf):
    zmqpubhashblock=tcp://127.0.0.1:28332
    (default CONFIRM_METHOD=wallet also needs a loaded wallet; CONFIRM_METHOD=getraw
     needs -txindex=1. CONFIRM_METHOD=scan needs neither.)

ZMQ 'hashblock' message (per official doc): 3 parts
    [ b"hashblock", <32-byte block hash, reversed byte order = RPC hex>, <4-byte LE seq> ]
The event is used only as a wake signal; the authoritative confirmation check is an
RPC query chosen by CONFIRM_METHOD (default: wallet gettransaction, no -txindex).

Usage:
    ./broadcast-then-broadcast-zmq.py <TX1_hex_or_file> <TX2_hex_or_file>

Env overrides:
    ELEMENTS_CLI    cli invocation           (default: "elements-cli")
    ZMQ_HASHBLOCK   zmq endpoint             (default: "tcp://127.0.0.1:28332")
    REQUIRED_CONF   confirmations to wait    (default: 1)
    TIMEOUT         give up after N seconds  (default: 3600)
    FALLBACK_POLL   safety re-scan interval  (default: 60 seconds)
    MAXFEERATE      sendrawtransaction cap; "0" disables it (default: unset)
    CONFIRM_METHOD  "wallet" (wallet gettransaction, no txindex; DEFAULT)
                  | "getraw" (needs txindex=1)
                  | "scan"   (block scan, no txindex)

NOTE on the default "wallet" method:
    gettransaction only knows transactions the wallet is aware of -- i.e. txs that
    spend from or pay to this wallet's own keys (the usual case when you broadcast
    your own crafted txs). It needs a loaded wallet (pass -rpcwallet=<name> in
    ELEMENTS_CLI when several are loaded) and works WITHOUT -txindex. If TX1 is NOT
    a wallet tx, use CONFIRM_METHOD=scan.
"""
import binascii
import json
import os
import shlex
import subprocess
import sys
import time

import zmq

CLI = shlex.split(os.environ.get("ELEMENTS_CLI", "elements-cli"))
ZMQ_ENDPOINT = os.environ.get("ZMQ_HASHBLOCK", "tcp://127.0.0.1:28332")
REQUIRED_CONF = int(os.environ.get("REQUIRED_CONF", "1"))
TIMEOUT = int(os.environ.get("TIMEOUT", "3600"))
FALLBACK_POLL = int(os.environ.get("FALLBACK_POLL", "60"))
MAXFEERATE = os.environ.get("MAXFEERATE", "")
CONFIRM_METHOD = os.environ.get("CONFIRM_METHOD", "wallet")


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", file=sys.stderr, flush=True)


def die(msg):
    print(f"error: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def rpc(*args):
    r = subprocess.run(CLI + [str(a) for a in args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"rpc failed: {' '.join(args)}")
    return r.stdout.strip()


def rpc_json(*args):
    return json.loads(rpc(*args))


def load_hex(a):
    if os.path.isfile(a):
        with open(a) as f:
            return "".join(f.read().split())
    return "".join(a.split())


def broadcast(hexstr):
    if MAXFEERATE != "":
        return rpc("sendrawtransaction", hexstr, MAXFEERATE)
    return rpc("sendrawtransaction", hexstr)


class WalletConfirmer:
    """Confirm via wallet gettransaction (DEFAULT). Needs a loaded wallet, no
    -txindex. Only sees transactions the wallet knows about (its own). While the
    tx is in the mempool, gettransaction reports confirmations=0 and no blockhash;
    once mined it reports blockhash + confirmations>0. A reorg drops it back to 0,
    or negative if a conflicting tx confirmed, so REQUIRED_CONF gates false starts.
    """

    def __init__(self, txid, start_height):
        self.txid = txid

    def blockhash_if_confirmed(self):
        try:
            info = rpc_json("gettransaction", self.txid)
        except RuntimeError:
            return None                       # not (yet) a wallet tx / not found
        bh = info.get("blockhash")
        if not bh:
            return None                       # still in mempool
        if int(info.get("confirmations", 0)) >= REQUIRED_CONF:   # negative = conflicted
            return bh
        return None


class RawConfirmer:
    """Confirm via getrawtransaction (needs -txindex=1 once the tx leaves the
    mempool). Reorg-safe: re-queries within the found block for in_active_chain.
    """

    def __init__(self, txid, start_height):
        self.txid = txid

    def blockhash_if_confirmed(self):
        try:
            info = rpc_json("getrawtransaction", self.txid, "true")
        except RuntimeError:
            return None                       # still in mempool / no txindex / unknown
        bh = info.get("blockhash")
        if not bh:
            return None                       # still in mempool
        if int(info.get("confirmations", 0)) >= REQUIRED_CONF:
            try:
                inblk = rpc_json("getrawtransaction", self.txid, "true", bh)
            except RuntimeError:
                return None
            if inblk.get("in_active_chain", True):
                return bh
        return None


class ScanConfirmer:
    """Confirm by scanning blocks from the broadcast height for txid; reorg-aware,
    needs NO -txindex and NO wallet. Works for any transaction."""

    def __init__(self, txid, start_height):
        self.txid = txid
        self.scan_from = start_height + 1
        self.found_hash = None
        self.found_height = 0

    def blockhash_if_confirmed(self):
        tip = int(rpc("getblockcount"))
        if self.found_hash is None:
            while self.scan_from <= tip:
                bh = rpc("getblockhash", self.scan_from)
                block = rpc_json("getblock", bh, "1")
                if self.txid in block.get("tx", []):
                    self.found_hash = bh
                    self.found_height = self.scan_from
                    break
                self.scan_from += 1
        if self.found_hash is not None:
            # reorg check: is our block still the one at that height?
            cur = None
            try:
                cur = rpc("getblockhash", self.found_height)
            except RuntimeError:
                pass
            if cur != self.found_hash:
                self.scan_from = self.found_height
                self.found_hash = None
                self.found_height = 0
                return None
            if tip - self.found_height + 1 >= REQUIRED_CONF:
                return self.found_hash
        return None


CONFIRMERS = {
    "wallet": WalletConfirmer,
    "getraw": RawConfirmer,
    "scan": ScanConfirmer,
}


def main():
    if len(sys.argv) != 3:
        die(f"usage: {sys.argv[0]} <TX1_hex_or_file> <TX2_hex_or_file>")
    confirmer_cls = CONFIRMERS.get(CONFIRM_METHOD)
    if confirmer_cls is None:
        die(f"unknown CONFIRM_METHOD: {CONFIRM_METHOD} (use wallet|getraw|scan)")
    tx1 = load_hex(sys.argv[1])
    tx2 = load_hex(sys.argv[2])
    if not tx1 or not tx2:
        die("empty transaction hex")

    # 1) Subscribe FIRST so we cannot miss the block that includes TX1.
    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.SUB)
    sock.setsockopt(zmq.RCVHWM, 0)          # don't drop under burst
    sock.connect(ZMQ_ENDPOINT)
    sock.setsockopt(zmq.SUBSCRIBE, b"hashblock")
    log(f"subscribed to hashblock at {ZMQ_ENDPOINT}")

    start_height = int(rpc("getblockcount"))

    # 2) Broadcast TX1.
    txid1 = broadcast(tx1)
    log(f"[1/3] TX1 broadcast, txid={txid1}")

    conf = confirmer_cls(txid1, start_height)
    blockhash = conf.blockhash_if_confirmed()   # immediate check (fast-mine race)

    # 3) Event loop: wake on each new block, re-check via the chosen RPC method.
    poller = zmq.Poller()
    poller.register(sock, zmq.POLLIN)
    deadline = time.time() + TIMEOUT
    log(f"[2/3] waiting for >= {REQUIRED_CONF} confirmation(s) "
        f"(method={CONFIRM_METHOD}, trigger=ZMQ) ...")
    while blockhash is None:
        remaining = deadline - time.time()
        if remaining <= 0:
            die(f"timeout after {TIMEOUT}s waiting for {txid1}")
        wait_ms = int(min(remaining, FALLBACK_POLL) * 1000)
        events = dict(poller.poll(timeout=wait_ms))
        if sock in events:
            topic, body, seq = sock.recv_multipart()
            newhash = binascii.hexlify(body).decode()   # = RPC block hash
            seqno = int.from_bytes(seq, "little")
            log(f"      block event #{seqno}: {newhash}")
        # Authoritative re-check regardless of ZMQ payload (also the fallback path).
        blockhash = conf.blockhash_if_confirmed()

    log(f"      TX1 confirmed in block {blockhash}")

    # 4) Broadcast TX2.
    txid2 = broadcast(tx2)
    log(f"[3/3] TX2 broadcast, txid={txid2}")
    print(txid2)   # stdout: the second txid, for piping


if __name__ == "__main__":
    main()

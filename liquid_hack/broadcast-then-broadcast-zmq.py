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
    TIMEOUT         give up after N seconds  (default: 900)
                    ~ (REQUIRED_CONF + a few blocks) x block interval; Liquid is
                    ~60s/block so 900s ~= 15 blocks. Raise for slower chains (e.g.
                    Bitcoin ~600s/block) or a large REQUIRED_CONF.
    FALLBACK_POLL   safety re-scan interval  (default: 60 seconds)
    MAXFEERATE      sendrawtransaction cap; "0" disables it (default: unset)
    CONFIRM_METHOD  "wallet" (wallet gettransaction, no txindex; DEFAULT)
                  | "getraw" (needs txindex=1)
                  | "scan"   (block scan, no txindex)
    REORG_CHECK     reorg re-verification: 0 = off (DEFAULT), 1 = on
                    Applies to the SCAN method only (getraw's redundant in_active_chain
                    re-check has been removed; wallet and getraw are inherently active-
                    chain-fresh). Set 1 only if sending TX2 requires TX1 to be FINAL and
                    you use scan. DEFAULT is OFF: the range-proof
                    cache-key-collision exploit this repo targets does NOT need it. TX1
                    (the primer) plants a genuine, VALID rangeproof result in the signers'
                    in-memory verification cache; TX2 (the exploit) reuses that entry via
                    a cache-key collision (forged variable-length fields concatenated
                    without length prefixes hash to the same key). That entry is written
                    at validation time in a process-static CuckooCache that a chain reorg
                    does NOT evict (the disconnect path never touches the cache). So a
                    reorg of TX1's block does not remove the planted entry and TX2 stays
                    valid; gating on "TX1 still on the active chain" would only needlessly
                    withhold a still-viable TX2.

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
import shutil
import subprocess
import sys
import time

try:
    import zmq
except ImportError:
    sys.stderr.write("error: pyzmq is required (pip install pyzmq)\n")
    sys.exit(1)

def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", file=sys.stderr, flush=True)


def die(msg):
    print(f"error: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def _int_env(name, default):
    """Parse a positive-integer env var, dying with a clean message (not a traceback)
    on a bad value -- so a typo can't silently misbehave or dump a stack trace."""
    raw = os.environ.get(name, default)
    try:
        n = int(raw)
    except ValueError:
        die(f"{name} must be a positive integer (got: {raw!r})")
    if n < 1:
        die(f"{name} must be >= 1 (got: {n})")
    return n


# elements-cli invocation: treat unset OR empty as the default; whitespace-only (which
# shlex splits to nothing) is an error rather than an accidental empty command.
CLI = shlex.split(os.environ.get("ELEMENTS_CLI") or "elements-cli")
if not CLI:
    die("ELEMENTS_CLI is empty")
ZMQ_ENDPOINT = os.environ.get("ZMQ_HASHBLOCK", "tcp://127.0.0.1:28332")
REQUIRED_CONF = _int_env("REQUIRED_CONF", "1")
TIMEOUT = _int_env("TIMEOUT", "900")
FALLBACK_POLL = _int_env("FALLBACK_POLL", "60")
MAXFEERATE = os.environ.get("MAXFEERATE", "")
CONFIRM_METHOD = os.environ.get("CONFIRM_METHOD", "wallet")
_reorg_raw = os.environ.get("REORG_CHECK", "0")
if _reorg_raw not in ("0", "1"):
    die(f"REORG_CHECK must be 0 or 1 (got: {_reorg_raw!r})")
REORG_CHECK = _reorg_raw == "1"   # off by default; see header note

# A confirmation query that FAILS is normally just "not confirmed yet", so the
# confirmers treat failure as "keep waiting". But a PERMANENT failure (wrong/absent
# -rpcwallet, getraw without -txindex once the tx leaves the mempool, an auth/chain
# misconfig) looks identical and would otherwise burn the whole TIMEOUT in silence.
# Surface the node's error text once (and again only if it changes) so the cause is
# visible while we keep retrying.
_last_query_err = None


def note_query_error(msg):
    global _last_query_err
    if msg == _last_query_err:
        return
    _last_query_err = msg
    log(f"confirmation query failed (still retrying): {msg or '<no error text>'}")


def rpc(*args):
    r = subprocess.run(CLI + [str(a) for a in args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        # args may contain non-str (e.g. an int height); stringify before joining
        # so the error message itself can't raise TypeError and mask the real failure.
        raise RuntimeError(r.stderr.strip()
                           or f"rpc failed: {' '.join(str(a) for a in args)}")
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
    -txindex. Only sees transactions the wallet knows about (its own).

    confirmations semantics (wallet gettransaction):
      > 0  active-chain depth; blockhash present         (state TxStateConfirmed)
      = 0  in mempool / not in any block; no blockhash
      < 0  conflicted: inputs re-spent by a mined tx; |value| = that tx's depth;
           no blockhash                            (state TxStateBlockConflicted)
    So blockhash present <=> confirmations >= 1, and a conflicted (negative) tx
    never carries a blockhash: it is already rejected by the `if not bh` guard
    below, so the >= REQUIRED_CONF test only gates depth (fires at REQUIRED_CONF>=2).
    A reorg moves a tx out of Confirmed back to 0/negative (its blockhash goes too).
    (getrawtransaction is never negative: a stale/side-chain block reports 0 WITH
    a blockhash -- see RawConfirmer.)

    Gap note: the confirm-decision -> TX2-broadcast window (in main) cannot be closed
    by any check. To make it HARMLESS when TX2 depends on TX1 finality, wait for
    finality depth -- on Liquid (reorgs <= 1 block) set REQUIRED_CONF=2, so TX1 has a
    child block and is final before TX2 is sent. gettransaction is read fresh each poll
    (already active-chain based), so REQUIRED_CONF=2 alone suffices; no extra check.
    """

    def __init__(self, txid, start_height):
        self.txid = txid

    def blockhash_if_confirmed(self):
        try:
            info = rpc_json("gettransaction", self.txid)
        except (RuntimeError, ValueError) as e:   # ValueError covers a bad-JSON response
            note_query_error(str(e))              # permanent misconfig (bad wallet/auth)
            return None                           # vs still-pending: surface it once, retry
        bh = info.get("blockhash")
        if not bh:
            return None                       # still in mempool
        if int(info.get("confirmations", 0)) >= REQUIRED_CONF:   # blockhash => conf>=1; gates depth only
            return bh
        return None


class RawConfirmer:
    """Confirm via getrawtransaction (needs -txindex=1 once the tx leaves the
    mempool). Re-queried fresh each poll; getrawtransaction's confirmations count
    ACTIVE-CHAIN depth (txindex is synced first; a stale block reports 0), so
    conf >= REQUIRED_CONF already means "REQUIRED_CONF-deep on the active chain." An
    in_active_chain re-query would be REDUNDANT, so it is omitted.

    confirmations semantics (getrawtransaction), unlike the wallet's:
      >= 1  block on the active chain (depth); blockhash present
      = 0   block exists but is stale/side-chain (off active); blockhash present
      mempool: NO confirmations field AND no blockhash -- the RPC skips its whole
               block branch (hashBlock is null), so `if not bh` catches it
    Never negative (no wallet conflict tracking). So an emitted `confirmations == 0`
    always means a stale block WITH a blockhash, which the >= REQUIRED_CONF test rejects.

    Gap note: the confirm-decision -> TX2-broadcast window (in main) cannot be closed
    by any check. To make it HARMLESS when TX2 depends on TX1 finality, set
    REQUIRED_CONF=2 on Liquid (reorgs <= 1 block) so TX1 is final before TX2 is sent.
    """

    def __init__(self, txid, start_height):
        self.txid = txid

    def blockhash_if_confirmed(self):
        try:
            info = rpc_json("getrawtransaction", self.txid, "true")
        except (RuntimeError, ValueError) as e:   # ValueError covers a bad-JSON response
            note_query_error(str(e))              # e.g. tx left mempool and no -txindex
            return None                           # surface it once, keep retrying
        bh = info.get("blockhash")
        if not bh:
            return None                       # still in mempool
        if int(info.get("confirmations", 0)) >= REQUIRED_CONF:   # active-chain depth
            return bh
        return None


class ScanConfirmer:
    """Confirm by scanning blocks from the broadcast height for txid; needs NO
    -txindex and NO wallet. Works for any transaction. Unlike wallet/getraw, scan
    counts depth from the REMEMBERED found_height, so it must re-verify found_hash is
    still the block at that height (REORG_CHECK=1) -- otherwise depth could be counted
    against an orphaned block. That re-check is NOT redundant here (it is for getraw),
    so it is kept, gated by REORG_CHECK (off by default; the cache-collision exploit
    does not need it).

    Gap note: to make the confirm -> TX2-broadcast window HARMLESS when TX2 depends on
    TX1 finality, use BOTH REORG_CHECK=1 (keeps the depth count on the active chain)
    AND REQUIRED_CONF=2 (finality depth) on Liquid."""

    def __init__(self, txid, start_height):
        self.txid = txid
        self.scan_from = start_height + 1
        self.found_hash = None
        self.found_height = 0

    def blockhash_if_confirmed(self):
        # A transient RPC failure must NOT be mistaken for "tx not in this block":
        # raising out of the loop leaves scan_from unadvanced (it never rewinds), so
        # the block is retried on the next tick rather than skipped -> the tx could
        # otherwise never be found and cause a false TIMEOUT. Mirrors the bash
        # confirmed_scan `|| return 0` hardening; the ZMQ FALLBACK_POLL re-check retries.
        try:
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
        except (RuntimeError, ValueError) as e:
            note_query_error(str(e))          # transient RPC error -> retry next tick
            return None
        if self.found_hash is not None:
            if REORG_CHECK:
                # reorg-safety (opt-in): is our block still the one at that height?
                # Only a SUCCESSFUL re-query is trusted: a transient getblockhash failure
                # must not be read as "reorged" (needless reset) nor "still there" (could
                # confirm against an orphan) -- skip this tick and retry.
                try:
                    cur = rpc("getblockhash", self.found_height)
                except (RuntimeError, ValueError):
                    return None
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
    if shutil.which(CLI[0]) is None:
        die(f"cli not found: {CLI[0]}")       # fail fast instead of a FileNotFoundError later
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
            # A 'hashblock' message is 3 parts [topic, hash, seq]; tolerate anything
            # off-spec rather than crashing on a tuple-unpack. The RPC re-check below
            # is authoritative either way -- the event is only a wake signal.
            parts = sock.recv_multipart()
            if len(parts) >= 2:
                newhash = binascii.hexlify(parts[1]).decode()   # = RPC block hash
                seqno = int.from_bytes(parts[2], "little") if len(parts) >= 3 else -1
                log(f"      block event #{seqno}: {newhash}")
            else:
                log(f"      block event (unexpected {len(parts)}-part message)")
        # Authoritative re-check regardless of ZMQ payload (also the fallback path).
        blockhash = conf.blockhash_if_confirmed()

    log(f"      TX1 confirmed in block {blockhash}")

    # 4) Broadcast TX2.
    txid2 = broadcast(tx2)
    log(f"[3/3] TX2 broadcast, txid={txid2}")
    print(txid2)   # stdout: the second txid, for piping


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("interrupted")
    except FileNotFoundError as e:
        die(f"command not found: {e}")
    except RuntimeError as e:
        die(str(e))                           # e.g. a sendrawtransaction / RPC failure

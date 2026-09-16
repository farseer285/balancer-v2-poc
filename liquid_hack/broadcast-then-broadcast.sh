#!/usr/bin/env bash
#
# broadcast-then-broadcast.sh
#
# Broadcast TX1, wait until it is confirmed in a block on the active chain,
# then broadcast TX2.
#
# The two raw transactions are OPAQUE hex inputs that YOU supply (a hex string
# or a path to a file containing hex). This script constructs no transaction
# contents; it is generic sequential-broadcast plumbing.
#
# RPC methods used (Bitcoin Core / Elements, per official reference):
#   sendrawtransaction <hex> [maxfeerate]   -> broadcast, returns txid
#   gettransaction     <txid> [watch] [v]   -> WALLET JSON: blockhash,
#                                              confirmations (own/wallet tx only,
#                                              no txindex needed) -- DEFAULT
#   getrawtransaction  <txid> true [bhash]  -> verbose JSON: blockhash,
#                                              confirmations, in_active_chain
#                                              (needs -txindex=1 out of mempool)
#   getblockcount / getblockhash / getblock -> block-scan fallback (no txindex)
#
# Usage:
#   ./broadcast-then-broadcast.sh <TX1_hex_or_file> <TX2_hex_or_file>
#
# Common env overrides:
#   ELEMENTS_CLI   full cli invocation      (default: "elements-cli")
#                  e.g. ELEMENTS_CLI="elements-cli -chain=liquidv1 -rpcwallet=w"
#   REQUIRED_CONF  confirmations to wait for (default: 1)
#   POLL_INTERVAL  seconds between polls     (default: 5)
#   TIMEOUT        give up after N seconds   (default: 3600)
#   MAXFEERATE     sendrawtransaction fee cap; "0" disables it (default: unset)
#   CONFIRM_METHOD "wallet" (wallet gettransaction, no txindex; DEFAULT)
#                | "getraw" (needs txindex=1)
#                | "scan"   (block scan, no txindex)
#   REORG_CHECK    reorg re-verification: 0 = off (DEFAULT), 1 = on
#                  Applies to the SCAN method only (getraw's redundant in_active_chain
#                  re-check has been removed; wallet and getraw are inherently active-
#                  chain-fresh). Set 1 only if sending TX2 requires TX1 to be FINAL and
#                  you use scan: it then re-verifies its found block is still at height.
#                  DEFAULT is OFF: the range-proof cache-key-collision exploit this
#                  repo targets does NOT need it. TX1 (the primer) plants a genuine,
#                  VALID rangeproof result in the signers' in-memory verification cache;
#                  TX2 (the exploit) reuses that entry via a cache-key collision (its
#                  forged variable-length fields, concatenated without length prefixes,
#                  hash to the same key). That entry is written at validation time in a
#                  process-static CuckooCache that a chain reorg does NOT evict (the
#                  disconnect path never touches the cache). So a reorg of TX1's block
#                  does not remove the planted entry and TX2 stays valid; gating on "TX1
#                  still on the active chain" would only needlessly withhold a
#                  still-viable TX2. Once TX1 is seen confirmed once, fire TX2.
#
# NOTE on the default "wallet" method:
#   gettransaction only knows transactions the wallet is aware of -- i.e. txs
#   that spend from or pay to this wallet's own keys (the usual case when you
#   broadcast your own crafted txs). It therefore needs a loaded wallet, so pass
#   -rpcwallet=<name> in ELEMENTS_CLI when more than one wallet is loaded. It
#   works WITHOUT -txindex. If your TX1 is NOT a wallet tx, use CONFIRM_METHOD=scan.

set -euo pipefail

# ----- config -----
read -ra CLI <<< "${ELEMENTS_CLI:-elements-cli}"
REQUIRED_CONF="${REQUIRED_CONF:-1}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
TIMEOUT="${TIMEOUT:-3600}"
MAXFEERATE="${MAXFEERATE:-}"
CONFIRM_METHOD="${CONFIRM_METHOD:-wallet}"
REORG_CHECK="${REORG_CHECK:-0}"          # 0 = off (default; see header note), 1 = on

# Result channel for the confirmed_* pollers. They MUST be called as PLAIN commands
# (not `bh=$(confirmed_scan ...)`), otherwise they run in a command-substitution
# subshell and their writes to the scan state (_scan_from/_found_hash/_found_height)
# are discarded every poll -- silently defeating the memoization. So instead of
# echoing the blockhash on stdout, each poller deposits it here (empty = not yet
# confirmed) and returns 0, and wait_confirmed reads it after the call.
_conf_result=""

log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

rpc() { "${CLI[@]}" "$@"; }

# Read hex from a file if the argument is an existing path, else treat it as
# literal hex. Whitespace/newlines are stripped either way.
load_hex() {
  local a="$1"
  if [[ -f "$a" ]]; then tr -d '[:space:]' < "$a"; else printf '%s' "$a" | tr -d '[:space:]'; fi
}

# Broadcast a raw tx; echo the returned txid.
broadcast() {
  local hex="$1"
  if [[ -n "$MAXFEERATE" ]]; then
    rpc sendrawtransaction "$hex" "$MAXFEERATE"
  else
    rpc sendrawtransaction "$hex"
  fi
}

# --- confirmation via wallet gettransaction (DEFAULT; needs NO -txindex) ---
# Works for transactions the wallet knows about (its own). While the tx sits in
# the mempool, gettransaction reports confirmations=0 and no blockhash. Once
# mined it reports blockhash + confirmations>0; a reorg drops it back to 0 (or
# negative if a conflicting tx confirmed), so REQUIRED_CONF gates false starts.
# Echoes the blockhash when confirmed with >= REQUIRED_CONF; echoes nothing
# while still pending.
# Gap note: the confirm-decision -> TX2-broadcast window (in main) cannot be closed by
# any check. To make it HARMLESS when TX2 depends on TX1 finality, wait for finality
# depth -- on Liquid (reorgs <= 1 block) set REQUIRED_CONF=2, so TX1 has a child block
# and is final before TX2 is sent. gettransaction is read fresh each poll (already
# active-chain based), so REQUIRED_CONF=2 alone suffices; no extra reorg check needed.
confirmed_wallet() {
  local txid="$1" json bh conf
  _conf_result=""                                      # result via global; see note above
  json=$(rpc gettransaction "$txid" 2>/dev/null) || return 0
  bh=$(jq -r '.blockhash // empty' <<< "$json")
  conf=$(jq -r '.confirmations // 0' <<< "$json")
  [[ -z "$bh" ]] && return 0                            # still in mempool
  (( conf >= REQUIRED_CONF )) && _conf_result="$bh"     # negative == conflicted -> stays empty
  return 0
}

# --- confirmation via getrawtransaction (needs -txindex=1 once tx leaves mempool) ---
# Re-queried fresh each poll; getrawtransaction's `confirmations` counts ACTIVE-CHAIN
# depth (txindex is synced to the current chain first, and a stale block reports 0), so
# `conf >= REQUIRED_CONF` already means "REQUIRED_CONF-deep on the active chain." An
# in_active_chain re-query would therefore be REDUNDANT, so it is intentionally omitted.
# Gap note: the confirm-decision -> TX2-broadcast window (in main) cannot be closed by
# any check. To make it HARMLESS when TX2 depends on TX1 finality, set REQUIRED_CONF=2
# on Liquid (reorgs <= 1 block) so TX1 has a child block and is final before TX2 is sent.
# Echoes the blockhash when confirmed with >= REQUIRED_CONF; nothing while still pending.
confirmed_getraw() {
  local txid="$1" json bh conf
  _conf_result=""                                      # result via global; see note above
  json=$(rpc getrawtransaction "$txid" true 2>/dev/null) || return 0
  bh=$(jq -r '.blockhash // empty' <<< "$json")
  conf=$(jq -r '.confirmations // 0' <<< "$json")
  [[ -z "$bh" ]] && return 0                            # still in mempool
  (( conf >= REQUIRED_CONF )) && _conf_result="$bh"     # active-chain depth; no re-check
  return 0
}

# --- confirmation via block scanning (works WITHOUT txindex) ---
# Remembers the block the tx landed in and waits for depth. Unlike wallet/getraw, scan
# counts depth from the REMEMBERED _found_height, so it must re-verify _found_hash is
# still the block at that height (REORG_CHECK=1) -- otherwise depth could be counted
# against an orphaned block. That re-check is NOT redundant here (it is for getraw), so
# it is kept, gated by REORG_CHECK (default off; the cache-collision exploit doesn't
# need it). Gap note: to make the confirm -> TX2-broadcast window HARMLESS when TX2
# depends on TX1 finality, use BOTH REORG_CHECK=1 (keeps the depth count on the active
# chain) AND REQUIRED_CONF=2 (finality depth) on Liquid.
_scan_from=""; _found_hash=""; _found_height=0
confirmed_scan() {
  local txid="$1" tip bh blk cur conf rc
  # Result via the _conf_result global (see note near its declaration). This memoizes
  # the found block ACROSS polls, so it MUST be called as a plain command, never as
  # `$(confirmed_scan ...)` -- a command-substitution subshell would discard every
  # write to _scan_from/_found_hash/_found_height and re-scan from the seed each poll.
  _conf_result=""
  # _scan_from MUST be seeded by main() with the tip captured BEFORE broadcast.
  # Refuse rather than seed it here: a post-broadcast seed would silently
  # reintroduce the fast-mine race (a block mined before the first poll would be
  # skipped). An empty value means confirmed_scan was called outside main()'s flow.
  [[ -n "$_scan_from" ]] || die "confirmed_scan: _scan_from not seeded (call via main with CONFIRM_METHOD=scan)"
  tip=$(rpc getblockcount) || return 0   # transient RPC error -> retry next poll
  if [[ -z "$_found_hash" ]]; then
    while (( _scan_from <= tip )); do
      # A transient RPC failure must NOT be mistaken for "tx not in this block": that
      # would advance _scan_from past the block, and since _scan_from never rewinds the
      # tx could then never be found -> false TIMEOUT. So on ANY getblockhash/getblock
      # failure, abandon THIS poll (retry next) WITHOUT advancing _scan_from.
      bh=$(rpc getblockhash "$_scan_from") || return 0
      blk=$(rpc getblock "$bh" 1)          || return 0
      # blk is now known-valid JSON, so jq's OWN exit code cleanly separates the cases
      # (a bare `jq -e` returning 1 would trip set -e, so it is guarded by `|| rc=$?`):
      #   0    = tx present in this block   -> found
      #   1    = tx absent from this block  -> advance to the next height
      #   >=2  = jq itself errored (not expected on valid JSON) -> retry, do NOT skip
      rc=0
      jq -e --arg t "$txid" 'any(.tx[]; . == $t)' >/dev/null 2>&1 <<< "$blk" || rc=$?
      case $rc in
        0) _found_hash="$bh"; _found_height="$_scan_from"; break ;;
        1) _scan_from=$(( _scan_from + 1 )) ;;
        *) return 0 ;;
      esac
    done
  fi
  if [[ -n "$_found_hash" ]]; then
    if [[ "$REORG_CHECK" == 1 ]]; then
      # reorg-safety (opt-in; see REORG_CHECK note in header): if our block is no longer
      # at that height it was reorged out -> rescan.
      cur=$(rpc getblockhash "$_found_height" 2>/dev/null || echo "")
      if [[ "$cur" != "$_found_hash" ]]; then
        _scan_from="$_found_height"; _found_hash=""; _found_height=0
        return 0
      fi
    fi
    conf=$(( tip - _found_height + 1 ))
    (( conf >= REQUIRED_CONF )) && _conf_result="$_found_hash"
  fi
  return 0
}

wait_confirmed() {
  local txid="$1" start now
  start=$(date +%s)
  while :; do
    # Call the poller as a PLAIN command (NOT `bh=$(confirmed_* ...)`): a command-
    # substitution subshell would drop confirmed_scan's cross-poll state each iteration.
    # The result comes back in the _conf_result global instead (empty = not yet).
    case "$CONFIRM_METHOD" in
      wallet) confirmed_wallet "$txid" ;;
      getraw) confirmed_getraw "$txid" ;;
      scan)   confirmed_scan   "$txid" ;;
      *)      die "unknown CONFIRM_METHOD: $CONFIRM_METHOD (use wallet|getraw|scan)" ;;
    esac
    [[ -n "$_conf_result" ]] && { printf '%s' "$_conf_result"; return 0; }
    now=$(date +%s)
    if (( now - start >= TIMEOUT )); then die "timeout after ${TIMEOUT}s waiting for $txid"; fi
    sleep "$POLL_INTERVAL"
  done
}

main() {
  [[ $# -eq 2 ]] || die "usage: $0 <TX1_hex_or_file> <TX2_hex_or_file>"
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v "${CLI[0]}" >/dev/null 2>&1 || die "cli not found: ${CLI[0]}"

  local tx1 tx2 txid1 blockhash txid2
  tx1=$(load_hex "$1"); tx2=$(load_hex "$2")
  [[ -n "$tx1" && -n "$tx2" ]] || die "empty transaction hex"

  # For the scan method, remember the tip BEFORE broadcasting so the block that
  # includes TX1 can never fall below the scan start (fast-mine race; mirrors the
  # ZMQ script capturing start_height pre-broadcast).
  [[ "$CONFIRM_METHOD" == scan ]] && _scan_from=$(( $(rpc getblockcount) + 1 ))

  log "[1/3] broadcasting TX1 ..."
  txid1=$(broadcast "$tx1")
  log "      TX1 accepted, txid=$txid1"

  log "[2/3] waiting for >= ${REQUIRED_CONF} confirmation(s) (method=${CONFIRM_METHOD}) ..."
  blockhash=$(wait_confirmed "$txid1")
  log "      TX1 confirmed in block $blockhash"

  log "[3/3] broadcasting TX2 ..."
  txid2=$(broadcast "$tx2")
  log "      TX2 accepted, txid=$txid2"

  printf '%s\n' "$txid2"   # stdout: the second txid, for piping
}

main "$@"

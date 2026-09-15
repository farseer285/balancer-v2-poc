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
confirmed_wallet() {
  local txid="$1" json bh conf
  json=$(rpc gettransaction "$txid" 2>/dev/null) || { printf ''; return 0; }
  bh=$(jq -r '.blockhash // empty' <<< "$json")
  conf=$(jq -r '.confirmations // 0' <<< "$json")
  [[ -z "$bh" ]] && { printf ''; return 0; }          # still in mempool
  if (( conf >= REQUIRED_CONF )); then                 # negative == conflicted
    printf '%s' "$bh"
  fi
  printf ''
}

# --- confirmation via getrawtransaction (needs -txindex=1 once tx leaves mempool) ---
# Echoes the blockhash when confirmed with >= REQUIRED_CONF on the active chain;
# echoes nothing while still pending.
confirmed_getraw() {
  local txid="$1" json bh conf active
  json=$(rpc getrawtransaction "$txid" true 2>/dev/null) || { printf ''; return 0; }
  bh=$(jq -r '.blockhash // empty' <<< "$json")
  conf=$(jq -r '.confirmations // 0' <<< "$json")
  [[ -z "$bh" ]] && { printf ''; return 0; }          # still in mempool
  if (( conf >= REQUIRED_CONF )); then
    # reorg-safety: re-query inside that specific block for in_active_chain
    active=$(rpc getrawtransaction "$txid" true "$bh" 2>/dev/null | jq -r '.in_active_chain // true')
    [[ "$active" == "true" ]] && printf '%s' "$bh"
  fi
  printf ''
}

# --- confirmation via block scanning (works WITHOUT txindex) ---
# Remembers the block the tx landed in and waits for depth; handles reorg.
_scan_from=""; _found_hash=""; _found_height=0
confirmed_scan() {
  local txid="$1" tip bh cur conf
  [[ -z "$_scan_from" ]] && _scan_from=$(( $(rpc getblockcount) + 1 ))
  tip=$(rpc getblockcount)
  if [[ -z "$_found_hash" ]]; then
    while (( _scan_from <= tip )); do
      bh=$(rpc getblockhash "$_scan_from")
      if rpc getblock "$bh" 1 | jq -e --arg t "$txid" 'any(.tx[]; . == $t)' >/dev/null 2>&1; then
        _found_hash="$bh"; _found_height="$_scan_from"; break
      fi
      _scan_from=$(( _scan_from + 1 ))
    done
  fi
  if [[ -n "$_found_hash" ]]; then
    cur=$(rpc getblockhash "$_found_height" 2>/dev/null || echo "")
    if [[ "$cur" != "$_found_hash" ]]; then          # reorged out -> rescan
      _scan_from="$_found_height"; _found_hash=""; _found_height=0
    else
      conf=$(( tip - _found_height + 1 ))
      (( conf >= REQUIRED_CONF )) && printf '%s' "$_found_hash"
    fi
  fi
  printf ''
}

wait_confirmed() {
  local txid="$1" start now bh
  start=$(date +%s)
  while :; do
    case "$CONFIRM_METHOD" in
      wallet) bh=$(confirmed_wallet "$txid") ;;
      getraw) bh=$(confirmed_getraw "$txid") ;;
      scan)   bh=$(confirmed_scan   "$txid") ;;
      *)      die "unknown CONFIRM_METHOD: $CONFIRM_METHOD (use wallet|getraw|scan)" ;;
    esac
    [[ -n "$bh" ]] && { printf '%s' "$bh"; return 0; }
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

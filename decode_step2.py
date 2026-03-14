#!/usr/bin/env python3
"""Extract Step 2 D-crash round extraction amounts (swap 3 of each round) from real attack."""
import json, sys

data = json.load(sys.stdin)
logs = data['logs']

swap_topic = '0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b'
pool1_id = '0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635'

weth = 'c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
oseth = 'f1c9acdc66974dfb6decb12aa385b9cd01190e38'
bpt = 'dacf5fa19b1f720111609043ac67a9818262850c'

pool1_swaps = []
for log in logs:
    topics = log['topics']
    if topics[0] == swap_topic and topics[1] == pool1_id:
        token_in = topics[2][26:].lower()
        token_out = topics[3][26:].lower()
        d = log['data'][2:]
        amount_in = int(d[:64], 16)
        amount_out = int(d[64:128], 16)
        pool1_swaps.append((token_in, token_out, amount_in, amount_out))

# Step 1: BPT -> WETH and BPT -> osETH alternating (drain)
# Step 2: groups of 3 (BPT->osETH drain1, BPT->osETH drain2, osETH->WETH extract)
# Step 3: WETH->BPT and osETH->BPT alternating (recovery)

# Find where Step 1 ends (last BPT->something swap before pattern changes)
# Step 1 pattern: BPT out WETH, BPT out osETH alternating
# Step 2 pattern: BPT out osETH, BPT out osETH, osETH out WETH (3 per round)

print(f"Total Pool 1 swaps: {len(pool1_swaps)}")

# Let's identify swap types
for i, s in enumerate(pool1_swaps):
    tin, tout = s[0], s[1]
    tin_name = 'WETH' if weth in tin else ('osETH' if oseth in tin else 'BPT')
    tout_name = 'WETH' if weth in tout else ('osETH' if oseth in tout else 'BPT')
    if i < 25 or i > len(pool1_swaps) - 15:
        print(f"  [{i:3d}] {tin_name:6s} -> {tout_name:6s}: in={s[2]:>30d} out={s[3]:>30d}")
    elif i == 25:
        print("  ...")

# Find Step 2 extraction amounts: these are osETH->WETH swaps (swap 3 of each round)
# In Step 2, every 3rd swap is osETH -> WETH
step2_extractions = []
for i, s in enumerate(pool1_swaps):
    tin, tout = s[0], s[1]
    # osETH is paid IN, WETH comes OUT
    if oseth in tin and weth in tout:
        step2_extractions.append(s[3])  # amount_out = WETH extracted

print(f"\nStep 2 WETH extraction amounts ({len(step2_extractions)} rounds):")
for i, amt in enumerate(step2_extractions):
    print(f"  Round {i}: {amt}")

print(f"\nTotal WETH extracted in Step 2: {sum(step2_extractions)} ({sum(step2_extractions)/1e18:.4f})")

# Print as Solidity array
print("\n// Solidity hardcoded amounts:")
print(f"amounts = new uint256[]({len(step2_extractions)});")
for i, amt in enumerate(step2_extractions):
    print(f"amounts[{i}] = {amt};")


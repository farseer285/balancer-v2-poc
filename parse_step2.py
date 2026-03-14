#!/usr/bin/env python3
import re, sys

BPT = "0xDACf5Fa19b1f720111609043ac67A9818262850c".lower()
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".lower()
OSETH = "0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38".lower()

swaps = []
with open("/tmp/swap_events.txt") as f:
    for line in f:
        m = re.search(r'tokenIn: (0x[0-9a-fA-F]+), tokenOut: (0x[0-9a-fA-F]+), amountIn: (\d+)', line)
        if not m: continue
        tokenIn = m.group(1).lower()
        tokenOut = m.group(2).lower()
        amountIn = int(m.group(3))
        m2 = re.search(r'amountOut: (\d+)', line)
        amountOut = int(m2.group(1))
        swaps.append((tokenIn, tokenOut, amountIn, amountOut))

print(f"Total swaps: {len(swaps)}")

# Print all swaps with labels
def tok_name(addr):
    if addr == BPT: return "BPT"
    if addr == WETH: return "WETH"
    if addr == OSETH: return "osETH"
    return addr[-6:]

print("\n=== All swaps ===")
for i, (ti, to, ai, ao) in enumerate(swaps):
    print(f"{i:>4}: {tok_name(ti):>6} -> {tok_name(to):>6}  in={ai:>25}  out={ao:>25}")

# Step 1: BPT -> WETH/osETH (tokenIn = BPT)
step1_end = 0
for i, (ti, to, ai, ao) in enumerate(swaps):
    if ti == BPT:
        step1_end = i + 1
    else:
        break

# Step 3: WETH/osETH -> BPT (tokenOut = BPT), find first occurrence after step1
step3_start = len(swaps)
for i in range(step1_end, len(swaps)):
    if swaps[i][1] == BPT:
        step3_start = i
        break

print(f"\nStep 1: swaps 0-{step1_end-1} ({step1_end} swaps)")
print(f"Step 2: swaps {step1_end}-{step3_start-1} ({step3_start-step1_end} swaps)")
print(f"Step 3: swaps {step3_start}-{len(swaps)-1} ({len(swaps)-step3_start} swaps)")

step2_swaps = swaps[step1_end:step3_start]
print(f"\nStep 2 swaps: {len(step2_swaps)}, rounds: {len(step2_swaps)/3:.1f}")

# Parse Step 2 rounds
rounds = []
for i in range(0, len(step2_swaps), 3):
    s1 = step2_swaps[i]   # WETH->osETH (drain most)
    s2 = step2_swaps[i+1] # WETH->osETH (drain remaining)
    s3 = step2_swaps[i+2] # osETH->WETH (extract)
    
    # Verify structure
    assert s1[0] == WETH and s1[1] == OSETH, f"Round {i//3}: swap1 should be WETH->osETH, got {s1[0][-6:]}->{s1[1][-6:]}"
    assert s2[0] == WETH and s2[1] == OSETH, f"Round {i//3}: swap2 should be WETH->osETH, got {s2[0][-6:]}->{s2[1][-6:]}"
    assert s3[0] == OSETH and s3[1] == WETH, f"Round {i//3}: swap3 should be osETH->WETH, got {s3[0][-6:]}->{s3[1][-6:]}"
    
    rounds.append({
        'drain1_out': s1[3],  # osETH amountOut (drain to targetBalance+1)
        'drain2_out': s2[3],  # osETH amountOut (drain remaining = targetBalance)
        'extract_out': s3[3], # WETH amountOut (extraction amount)
        'extract_in': s3[2],  # osETH amountIn
    })

print(f"\nParsed {len(rounds)} rounds")
print(f"\n=== Step 2 Round Details ===")
print(f"{'Round':>5} {'drain1_out':>15} {'drain2_out':>15} {'extract_WETH_out':>20} {'extract_osETH_in':>20}")
for i, r in enumerate(rounds):
    print(f"{i:>5} {r['drain1_out']:>15} {r['drain2_out']:>15} {r['extract_out']:>20} {r['extract_in']:>20}")

# Print the extract amounts as a Solidity array
print("\n=== Solidity array for extract amounts (WETH out) ===")
amounts = [r['extract_out'] for r in rounds]
print(f"uint256[{len(amounts)}] memory step2ExtractAmounts;")
for i, a in enumerate(amounts):
    print(f"step2ExtractAmounts[{i}] = {a};")

# Print targetBalance values
print("\n=== Target balances (drain2_out = targetBalance) ===")
tbs = set(r['drain2_out'] for r in rounds)
print(f"Unique targetBalance values: {sorted(tbs)}")


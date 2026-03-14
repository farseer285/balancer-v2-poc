#!/usr/bin/env python3
"""Calculate swap fee from real attack swap data."""
import re

OSETH_POOL = '0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635'
BPT  = '0xdacf5fa19b1f720111609043ac67a9818262850c'.lower()
WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'.lower()
OSETH= '0xf1c9acdc66974dfb6decb12aa385b9cd01190e38'.lower()

def tok(addr):
    if addr == BPT: return 'BPT'
    if addr == WETH: return 'WETH'
    if addr == OSETH: return 'osETH'
    return addr[-8:]

swaps = []
with open('/tmp/swap_events.txt') as f:
    for line in f:
        m = re.search(r'poolId: (0x[0-9a-fA-F]+), tokenIn: (0x[0-9a-fA-F]+), tokenOut: (0x[0-9a-fA-F]+), amountIn: (\d+), amountOut: (\d+)', line)
        if m:
            swaps.append((m.group(1).lower(), m.group(2).lower(), m.group(3).lower(), int(m.group(4)), int(m.group(5))))

print(f"Total swap events parsed: {len(swaps)}")
print()

# Show first few osETH pool swaps
print("=== First osETH pool swaps (Step 1 drain) ===")
for i, (poolId, tIn, tOut, aIn, aOut) in enumerate(swaps[:25]):
    if poolId == OSETH_POOL:
        print(f"  swap {i}: {tok(tIn)}->{tok(tOut)}, amountIn={aIn}, amountOut={aOut}")

# For GIVEN_OUT swaps in ComposableStablePool:
# The pool computes amountIn without fee, then divides by (1 - fee):
#   amountIn = amountIn_nofee / (1 - fee)
# So: fee = 1 - amountIn_nofee / amountIn
#
# But we only see final amountIn (with fee included).
# However, for BPT swaps (BPT is virtual), fee is NOT charged.
# For token-to-token swaps, fee IS charged.
#
# In Step 2 D-crash rounds, each round has 3 swaps:
#   1. WETH->osETH (drain1): fee charged
#   2. WETH->osETH (drain2): fee charged  
#   3. osETH->WETH (extract): fee charged
#
# We can't directly compute fee from just amountIn/amountOut without
# knowing the pool balances and invariant at that point.
#
# The simplest way is to query getSwapFeePercentage() which we already did.
# But let's try to verify from the onSwap trace data.

print()
print("=== Step 2 first round (swaps 22-24) ===")
for i in range(22, 25):
    if i < len(swaps):
        poolId, tIn, tOut, aIn, aOut = swaps[i]
        if poolId == OSETH_POOL:
            ratio = aIn / aOut if aOut > 0 else 0
            print(f"  swap {i}: {tok(tIn)}->{tok(tOut)}, in={aIn}, out={aOut}, ratio={ratio:.6f}")

# For the D-crash drain swaps where pool is nearly empty (only ~17 wei left),
# the StableSwap math becomes nearly linear (1:1 exchange).
# With fee=0.01%, GIVEN_OUT: amountIn = ceil(amountOut / (1 - 0.0001))
# For small amounts: amountIn ≈ amountOut * 10000 / 9999
# Let's check the small drain swaps (drain1/drain2 in Step 2)
print()
print("=== Checking fee from small Step 2 drain swaps ===")
print("For tiny swaps near empty pool, exchange rate ≈ 1:1")
print("So amountIn/amountOut ≈ 1/(1-fee) if GIVEN_OUT")
print()
for i in range(22, 112):
    if i >= len(swaps): break
    poolId, tIn, tOut, aIn, aOut = swaps[i]
    if poolId != OSETH_POOL: continue
    # drain swaps: WETH->osETH with small amounts
    if tok(tIn) == 'WETH' and tok(tOut) == 'osETH' and aOut <= 100:
        implied_fee = 1.0 - aOut / aIn if aIn > 0 else 0
        print(f"  swap {i}: WETH->osETH, in={aIn}, out={aOut}, implied_fee={implied_fee:.6f} ({implied_fee*100:.4f}%)")


#!/usr/bin/env python3
"""Compute per-pool deltas from the real attack swap events."""
import re

BPT = "0xDACf5Fa19b1f720111609043ac67A9818262850c".lower()
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".lower()
OSETH = "0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38".lower()
OSETH_POOL = "0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635"

swaps = []
with open("/tmp/swap_events.txt") as f:
    for line in f:
        m = re.search(r'poolId: (0x[0-9a-fA-F]+), tokenIn: (0x[0-9a-fA-F]+), tokenOut: (0x[0-9a-fA-F]+), amountIn: (\d+)', line)
        if not m: continue
        poolId = m.group(1).lower()
        tokenIn = m.group(2).lower()
        tokenOut = m.group(3).lower()
        amountIn = int(m.group(4))
        m2 = re.search(r'amountOut: (\d+)', line)
        amountOut = int(m2.group(1))
        swaps.append((poolId, tokenIn, tokenOut, amountIn, amountOut))

# Compute deltas for osETH pool swaps only (user perspective)
# delta[token] += amountIn (user sends to pool)
# delta[token] -= amountOut (user receives from pool)
pool_deltas = {}
other_deltas = {}

for poolId, tokenIn, tokenOut, amountIn, amountOut in swaps:
    if poolId == OSETH_POOL:
        pool_deltas[tokenIn] = pool_deltas.get(tokenIn, 0) + amountIn
        pool_deltas[tokenOut] = pool_deltas.get(tokenOut, 0) - amountOut
    else:
        other_deltas[tokenIn] = other_deltas.get(tokenIn, 0) + amountIn
        other_deltas[tokenOut] = other_deltas.get(tokenOut, 0) - amountOut

def tok_name(addr):
    if addr == BPT: return "BPT"
    if addr == WETH: return "WETH"
    if addr == OSETH: return "osETH"
    return addr[-8:]

print("=== osETH Pool-Only Deltas (positive=owe, negative=receive) ===")
for addr in [WETH, BPT, OSETH]:
    d = pool_deltas.get(addr, 0)
    sign = "+" if d >= 0 else "-"
    print(f"  {tok_name(addr):>6}: {sign}{abs(d)}")

print("\n=== Other Pools Deltas ===")
for addr, d in sorted(other_deltas.items(), key=lambda x: abs(x[1]), reverse=True):
    sign = "+" if d >= 0 else "-"
    print(f"  {tok_name(addr):>8}: {sign}{abs(d)}")

print("\n=== Total Deltas (all pools) ===")
total = {}
for d in [pool_deltas, other_deltas]:
    for addr, v in d.items():
        total[addr] = total.get(addr, 0) + v
for addr in [WETH, BPT, OSETH]:
    d = total.get(addr, 0)
    sign = "+" if d >= 0 else "-"
    print(f"  {tok_name(addr):>6}: {sign}{abs(d)}")

# PoC deltas for comparison
poc_weth  = -4623598991412800585286
poc_bpt   = -44154666372672521144
poc_oseth = -6851122950337969068711

print("\n=== Comparison: osETH Pool-Only vs PoC ===")
print(f"{'':15s} {'Pool-Only':>30s} {'PoC':>30s} {'Diff':>30s}")
for name, addr in [("WETH", WETH), ("BPT", BPT), ("osETH", OSETH)]:
    real_d = pool_deltas.get(addr, 0)
    poc_d = {"WETH": poc_weth, "BPT": poc_bpt, "osETH": poc_oseth}[name]
    diff = poc_d - real_d
    print(f"{name:15s} {real_d/1e18:>30.6f} {poc_d/1e18:>30.6f} {diff/1e18:>+30.6f}")


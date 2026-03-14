#!/usr/bin/env python3
# PoC deltas (negative = attacker receives)
poc_weth  = 4470191137259597824262
poc_bpt   = 34144656379549623441
poc_oseth = 6850066818318093573214

# Real attack batchSwap deltas
real_weth  = 4259843451780587743322
real_bpt   = 20413668455251157822
real_oseth = 1963838806164214870519

print("=== COMPARISON: PoC vs Real Attack ===")
print(f"{'':20s} {'PoC':>25s} {'Real Attack':>25s} {'Diff':>25s}")
print(f"{'WETH received':20s} {poc_weth/1e18:>25.6f} {real_weth/1e18:>25.6f} {(poc_weth-real_weth)/1e18:>+25.6f}")
print(f"{'BPT received':20s} {poc_bpt/1e18:>25.6f} {real_bpt/1e18:>25.6f} {(poc_bpt-real_bpt)/1e18:>+25.6f}")
print(f"{'osETH received':20s} {poc_oseth/1e18:>25.6f} {real_oseth/1e18:>25.6f} {(poc_oseth-real_oseth)/1e18:>+25.6f}")
print()
print("=== TOTAL VALUE (assuming osETH ~ 1 ETH) ===")
poc_total = poc_weth + poc_oseth
real_total = real_weth + real_oseth
print(f"PoC total (ETH-equiv):  {poc_total/1e18:.2f}")
print(f"Real total (ETH-equiv): {real_total/1e18:.2f}")
print(f"Difference:             {(poc_total-real_total)/1e18:+.2f}")
print()
print("NOT MATCHING - PoC only swaps within osETH pool.")
print("Real attack also routes through wstETH and other pools.")


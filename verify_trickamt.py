#!/usr/bin/env python3
"""Verify trickAmt = floor(1e18 / (sf - 1e18)) formula"""

ONE = 10**18

# Pool 1: osETH/WETH - actual on-chain value at block 23717396
sf = 1058109553424427048
delta = sf - ONE
trickAmt = ONE // delta

print("=== Pool 1 (osETH/WETH) ===")
print(f"  scalingFactor (on-chain at block 23717396) = {sf}")
print(f"  delta = sf - 1e18 = {delta}")
print(f"  trickAmt = floor(1e18 / delta) = floor({ONE/delta:.4f}) = {trickAmt}")
print(f"  Real attack trickAmt = 17")
print(f"  MATCH: {trickAmt == 17}")
print()

# Verify the precision loss property
print("  Verifying mulDown(x, sf) == x:")
for t in [16, 17, 18, 19]:
    upscaled = t * sf // ONE
    print(f"    mulDown({t}, sf) = {upscaled}, unchanged = {upscaled == t}")

print()
print(f"  Why: {trickAmt} * {delta} = {trickAmt * delta} < {ONE}? {trickAmt * delta < ONE}")
print(f"        {trickAmt+1} * {delta} = {(trickAmt+1) * delta} < {ONE}? {(trickAmt+1) * delta < ONE}")

print()
print("=" * 60)

# Pool 2: wstETH/WETH
print()
print("=== Pool 2 (wstETH/WETH) ===")
print("  Real attack trickAmt = 4")
print("  If floor(1e18/(sf-1e18)) = 4, then sf-1e18 in (2e17, 2.5e17]")
print("  So sf in (1.2e18, 1.25e18] -- consistent with wstETH rate ~1.2x")

print()
print("=" * 60)
print()
print("CONCLUSION:")
print("  trickAmt is analytically derived: trickAmt = floor(1e18 / (scalingFactor - 1e18))")
print("  It is the MAXIMUM value x such that mulDown(x, sf) == x (precision loss is total)")
print("  No brute-force search needed for this parameter.")


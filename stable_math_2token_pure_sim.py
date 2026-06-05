#!/usr/bin/env python3
# 2-Token Pool Pure Theoretical Formula Simulation Test
def div_down(a, b): return a // b
def div_up(a, b): return (a + b - 1) // b

# Input the exact extreme parameters that caused the first group breakdown
amp = 200000
_AMP_PRECISION = 1000
invariant = 145787508
bO = 155167  # Balance of the other token

# 1. Directly calculate C using the pure formula (perfectly eliminating the old balance 1630 and its caused P_D truncation)
D3 = invariant * invariant * invariant
c_pure = div_up(D3 * _AMP_PRECISION, 8 * amp * bO)

# 2. Calculate the first-order coefficient b (free from old balance contamination, matching official logic)
ampTimesTotal = amp * 2
b = bO + div_down(invariant, ampTimesTotal) * _AMP_PRECISION

# 3. Run the standard Newton-Raphson method to solve for the target balance
tokenBalance = div_up(invariant * invariant + c_pure, invariant + b)
for i in range(255):
    prev = tokenBalance
    tokenBalance = div_up(tokenBalance * tokenBalance + c_pure, tokenBalance * 2 + b - invariant)
    if abs(tokenBalance - prev) <= 1:
        break

# 4. Substitute the calculated pure new balance back into the standard _calculateInvariant to reverse-engineer the pool invariant
s = tokenBalance + bO
inv = s
for i in range(255):
    D_P = inv
    D_P = (D_P * inv) // (tokenBalance * 2)
    D_P = (D_P * inv) // (bO * 2)
    prevInv = inv
    num = (((ampTimesTotal * s) // _AMP_PRECISION) + D_P * 2) * inv
    den = (((ampTimesTotal - _AMP_PRECISION) * inv) // _AMP_PRECISION) + 3 * D_P
    inv = num // den
    if abs(inv - prevInv) <= 1:
        break

print(f"Token balance calculated by pure formula (bW): {tokenBalance}")
print(f"Recalculated new invariant (D'): {inv}")
print(f"Target invariant (D): {invariant}")
print(f"Pure physical truncation error (D' - D): {inv - invariant}")

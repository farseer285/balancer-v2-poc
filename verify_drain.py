#!/usr/bin/env python3
# Verify the real attack's drain formula: amount = (remaining - target) * 99 / 100

weth_balance = 4922356564867078856521
oseth_balance = 6851581236039298760900
target = 67000

print("=== WETH: formula (remaining - target) * 99 / 100 ===")
remaining = weth_balance
real_weth = [4873132999218408001625, 48731329992184080017, 487313299921840800, 4873132999218408, 48731329992184, 487313299922, 4873132999, 48731330, 487313, 4873, 50]
for i in range(20):
    excess = remaining - target
    amount = excess * 99 // 100
    if amount == 0:
        break
    real = real_weth[i] if i < len(real_weth) else "N/A"
    match = "MATCH" if i < len(real_weth) and amount == real_weth[i] else "DIFF"
    print(f"  step[{i}]: calc={amount}, real={real} [{match}]")
    remaining -= amount
print(f"  remaining: {remaining}")

print()
print("=== osETH: formula (remaining - target) * 99 / 100 ===")
remaining = oseth_balance
real_oseth = [6783065423678905706961, 67830654236789057069, 678306542367890571, 6783065423678906, 67830654236789, 678306542367, 6783065424, 67830654, 678307, 6783, 69]
for i in range(20):
    excess = remaining - target
    amount = excess * 99 // 100
    if amount == 0:
        break
    real = real_oseth[i] if i < len(real_oseth) else "N/A"
    match = "MATCH" if i < len(real_oseth) and amount == real_oseth[i] else "DIFF"
    print(f"  step[{i}]: calc={amount}, real={real} [{match}]")
    remaining -= amount
print(f"  remaining: {remaining}")


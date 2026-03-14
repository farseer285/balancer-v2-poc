#!/usr/bin/env python3
weth_balance = 4922356564867078856521
oseth_balance = 6851581236039298760900
target = 67000

print("=== PoC WETH Drain (geometric 1/100) ===")
amount = weth_balance * 99 // 100
remaining = weth_balance
poc_weth = []
for i in range(15):
    if amount == 0 or remaining <= target:
        break
    if remaining - amount <= target:
        poc_weth.append(remaining - target)
        print(f"  step[{i}]: {remaining - target} (cleanup)")
        remaining = target
        break
    poc_weth.append(amount)
    print(f"  step[{i}]: {amount}")
    remaining -= amount
    amount = amount // 100
print(f"  remaining: {remaining}, steps: {len(poc_weth)}")

print()
print("=== Real attack WETH drain amounts ===")
real_weth = [4873132999218408001625, 48731329992184080017, 487313299921840800, 4873132999218408, 48731329992184, 487313299922, 4873132999, 48731330, 487313, 4873, 50]
for i, a in enumerate(real_weth):
    print(f"  step[{i}]: {a}")
print(f"  sum: {sum(real_weth)}, remaining: {weth_balance - sum(real_weth)}")

print()
print("=== Comparison ===")
for i in range(max(len(poc_weth), len(real_weth))):
    p = poc_weth[i] if i < len(poc_weth) else 0
    r = real_weth[i] if i < len(real_weth) else 0
    match = "MATCH" if p == r else "DIFF"
    print(f"  step[{i}]: poc={p}, real={r} [{match}]")

print()
print("=== PoC osETH Drain (geometric 1/100) ===")
amount = oseth_balance * 99 // 100
remaining = oseth_balance
poc_oseth = []
for i in range(15):
    if amount == 0 or remaining <= target:
        break
    if remaining - amount <= target:
        poc_oseth.append(remaining - target)
        print(f"  step[{i}]: {remaining - target} (cleanup)")
        remaining = target
        break
    poc_oseth.append(amount)
    print(f"  step[{i}]: {amount}")
    remaining -= amount
    amount = amount // 100
print(f"  remaining: {remaining}, steps: {len(poc_oseth)}")

print()
print("=== Real attack osETH drain amounts ===")
real_oseth = [6783065423678905706961, 67830654236789057069, 678306542367890571, 6783065423678906, 67830654236789, 678306542367, 6783065424, 67830654, 678307, 6783, 69]
for i, a in enumerate(real_oseth):
    print(f"  step[{i}]: {a}")
print(f"  sum: {sum(real_oseth)}, remaining: {oseth_balance - sum(real_oseth)}")

print()
print("=== osETH Comparison ===")
for i in range(max(len(poc_oseth), len(real_oseth))):
    p = poc_oseth[i] if i < len(poc_oseth) else 0
    r = real_oseth[i] if i < len(real_oseth) else 0
    match = "MATCH" if p == r else "DIFF"
    print(f"  step[{i}]: poc={p}, real={r} [{match}]")


#!/usr/bin/env python3
import json, subprocess

result = subprocess.run([
    "cast", "receipt",
    "0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742",
    "--rpc-url", "https://ethereum-rpc.publicnode.com",
    "--json"
], capture_output=True, text=True)

data = json.loads(result.stdout)
logs = data['logs']

swap_topic = '0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b'
pool1_id = '0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635'
vault = '0xba12222222228d8ba445958a75a0704d566bf2c8'

weth = 'c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
oseth = 'f1c9acdc66974dfb6decb12aa385b9cd01190e38'
bpt = 'dacf5fa19b1f720111609043ac67a9818262850c'

def tname(addr):
    a = addr.lower()
    if weth in a: return 'WETH'
    if oseth in a: return 'osETH'
    if bpt in a: return 'BPT'
    return addr[-8:]

step1_weth = 0
step1_oseth = 0
step1_bpt_cost = 0
step3_weth = 0
step3_oseth = 0
step3_bpt_received = 0
step2_count = 0

for log in logs:
    topics = log['topics']
    if log['address'].lower() != vault.lower():
        continue
    if topics[0] != swap_topic:
        continue
    if topics[1] != pool1_id:
        continue
    token_in = '0x' + topics[2][26:]
    token_out = '0x' + topics[3][26:]
    d = log['data'][2:]
    amount_in = int(d[:64], 16)
    amount_out = int(d[64:128], 16)
    tin = tname(token_in)
    tout = tname(token_out)

    if tin == 'BPT' and tout == 'WETH':
        step1_bpt_cost += amount_in
        step1_weth += amount_out
    elif tin == 'BPT' and tout == 'osETH':
        step1_bpt_cost += amount_in
        step1_oseth += amount_out
    elif tout == 'BPT' and tin == 'WETH':
        step3_weth += amount_in
        step3_bpt_received += amount_out
    elif tout == 'BPT' and tin == 'osETH':
        step3_oseth += amount_in
        step3_bpt_received += amount_out
    else:
        step2_count += 1

print("=== STEP 1: Drain pool (BPT -> tokens) ===")
print(f"  BPT spent:       {step1_bpt_cost/1e18:.4f}")
print(f"  WETH received:   {step1_weth/1e18:.4f}")
print(f"  osETH received:  {step1_oseth/1e18:.4f}")
print(f"  Total tokens:    {(step1_weth + step1_oseth)/1e18:.4f}")

print(f"\n=== STEP 2: Cycling ({step2_count} swaps) ===")

print(f"\n=== STEP 3: Buy back BPT (tokens -> BPT) ===")
print(f"  WETH spent:      {step3_weth/1e18:.4f}")
print(f"  osETH spent:     {step3_oseth/1e18:.4f}")
print(f"  Total cost:      {(step3_weth + step3_oseth)/1e18:.4f}")
print(f"  BPT received:    {step3_bpt_received/1e18:.4f}")

print(f"\n=== NET from Pool 1 ===")
net_bpt = step3_bpt_received - step1_bpt_cost
net_tokens = (step1_weth + step1_oseth) - (step3_weth + step3_oseth)
print(f"  BPT surplus:     {net_bpt/1e18:.4f}")
print(f"  Token profit:    {net_tokens/1e18:.4f} ETH")
print(f"  Step 3 cost:     {(step3_weth + step3_oseth)/1e18:.4f} ETH")

print(f"\n=== FORMULA vs REAL ===")
formula_extracted = 11773937800906377483421
formula_cycling = 131639
formula_repayment = 2365
formula_profit = formula_extracted - formula_cycling - formula_repayment

print(f"  Formula tokensExtracted:  {formula_extracted/1e18:.4f}")
print(f"  Real Step 1 tokens:       {(step1_weth + step1_oseth)/1e18:.4f}")
print(f"  Diff (Step 1):            {(formula_extracted - step1_weth - step1_oseth)/1e18:.4f}")
print(f"  Formula repaymentCost:    {formula_repayment/1e18:.10f}")
print(f"  Real Step 3 cost:         {(step3_weth + step3_oseth)/1e18:.4f}")
print(f"  Diff (Step 3):            {((step3_weth + step3_oseth) - formula_repayment)/1e18:.4f}")
print(f"  Formula profit:           {formula_profit/1e18:.4f}")
print(f"  Real token profit:        {net_tokens/1e18:.4f}")
print(f"  Diff (profit):            {(formula_profit/1e18 - net_tokens/1e18):.4f}")


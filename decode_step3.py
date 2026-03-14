import json, subprocess

result = subprocess.run(
    ['cast', 'receipt', '0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742',
     '--rpc-url', 'https://ethereum-rpc.publicnode.com', '--json'],
    capture_output=True, text=True
)
receipt = json.loads(result.stdout)

vault = "0xba12222222228d8ba445958a75a0704d566bf2c8"
swap_sig = "0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b"
pool_id = "0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635"

bpt_addr = "0xdacf5fa19b1f720111609043ac67a9818262850c"
weth_addr = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
oseth_addr = "0xf1c9acdc66974dfb6decb12aa385b9cd01190e38"

swaps = []
for log in receipt['logs']:
    if log['address'].lower() == vault and log['topics'][0] == swap_sig:
        pool = log['topics'][1]
        if pool.lower() == pool_id.lower():
            token_in = ('0x' + log['topics'][2][26:]).lower()
            token_out = ('0x' + log['topics'][3][26:]).lower()
            data = log['data'][2:]
            amount_in = int(data[:64], 16)
            amount_out = int(data[64:], 16)
            swaps.append({
                'token_in': token_in,
                'token_out': token_out,
                'amount_in': amount_in,
                'amount_out': amount_out
            })

print(f"Total swaps for osETH/WETH pool: {len(swaps)}")

step1, step2, step3 = [], [], []
for s in swaps:
    if s['token_in'] == bpt_addr:
        step1.append(s)
    elif s['token_out'] == bpt_addr:
        step3.append(s)
    else:
        step2.append(s)

print(f"Step 1 (BPT->token): {len(step1)} swaps")
print(f"Step 2 (token<->token): {len(step2)} swaps")
print(f"Step 3 (token->BPT): {len(step3)} swaps")
print()

print("=== Step 3 details (token -> BPT) ===")
total_token_cost = 0
total_bpt_bought = 0
for i, s in enumerate(step3):
    token_name = "WETH" if s['token_in'] == weth_addr else "osETH"
    print(f"  Swap {i}: {token_name} in={s['amount_in']} -> BPT out={s['amount_out']}")
    total_token_cost += s['amount_in']
    total_bpt_bought += s['amount_out']

print(f"\nTotal BPT bought: {total_bpt_bought} ({total_bpt_bought/1e18:.4f} BPT)")
print(f"Total token cost: {total_token_cost} ({total_token_cost/1e18:.4f} ETH)")

# Also show Step 1 totals
print("\n=== Step 1 summary ===")
total_bpt_sold = 0
total_tokens_out = 0
for s in step1:
    total_bpt_sold += s['amount_in']
    total_tokens_out += s['amount_out']
print(f"Total BPT sold: {total_bpt_sold} ({total_bpt_sold/1e18:.4f})")
print(f"Total tokens received: {total_tokens_out} ({total_tokens_out/1e18:.4f})")

# === Track pool balances through all steps ===
# Get initial balances from pre-attack block
init_result = subprocess.run(
    ['cast', 'call', '0xBA12222222228d8Ba445958a75a0704d566BF2C8',
     'getPoolTokens(bytes32)(address[],uint256[],uint256)',
     pool_id,
     '--rpc-url', 'https://ethereum-rpc.publicnode.com',
     '--block', '23717396'],
    capture_output=True, text=True
)
lines = init_result.stdout.strip().split('\n')
# Parse the uint256[] balances line (2nd array)
# Format: [val1, val2, val3]
bal_line = lines[1].strip()
import re
# Each balance entry looks like "4922356564867078856521 [4.922e21]"
# Split by comma, then extract the first integer from each part
bal_parts = bal_line.strip('[] ').split(',')
bal_vals = []
for part in bal_parts:
    # First contiguous digits in each comma-separated section
    m = re.search(r'\d+', part.strip())
    bal_vals.append(int(m.group()))
init_weth = bal_vals[0]
init_bpt = bal_vals[1]
init_oseth = bal_vals[2]

# Get totalSupply
ts_result = subprocess.run(
    ['cast', 'call', '0xDACf5Fa19b1f720111609043ac67A9818262850c',
     'totalSupply()(uint256)',
     '--rpc-url', 'https://ethereum-rpc.publicnode.com',
     '--block', '23717396'],
    capture_output=True, text=True
)
total_supply = int(re.findall(r'\d+', ts_result.stdout.strip())[0])
init_virtual_supply = total_supply - init_bpt

print(f"\n=== Pool Balance Tracking ===")
print(f"Initial state (block 23717396):")
print(f"  WETH:  {init_weth}")
print(f"  BPT:   {init_bpt}")
print(f"  osETH: {init_oseth}")
print(f"  totalSupply: {total_supply}")
print(f"  virtualSupply: {init_virtual_supply}")

# Track through all swaps
bW = init_weth
bO = init_oseth
bBPT = init_bpt  # registered BPT balance

for i, s in enumerate(step1):
    # BPT in, token out
    bBPT += s['amount_in']  # BPT enters pool
    if s['token_out'] == weth_addr:
        bW -= s['amount_out']
    elif s['token_out'] == oseth_addr:
        bO -= s['amount_out']

vs_after_step1 = total_supply - bBPT
print(f"\nAfter Step 1 ({len(step1)} exits):")
print(f"  WETH:  {bW}")
print(f"  osETH: {bO}")
print(f"  registeredBPT: {bBPT}")
print(f"  virtualSupply: {vs_after_step1}")

for i, s in enumerate(step2):
    if s['token_in'] == weth_addr:
        bW += s['amount_in']
    elif s['token_in'] == oseth_addr:
        bO += s['amount_in']
    if s['token_out'] == weth_addr:
        bW -= s['amount_out']
    elif s['token_out'] == oseth_addr:
        bO -= s['amount_out']

vs_after_step2 = total_supply - bBPT
print(f"\nAfter Step 2 ({len(step2)} cycling swaps):")
print(f"  WETH:  {bW}")
print(f"  osETH: {bO}")
print(f"  registeredBPT: {bBPT}")
print(f"  virtualSupply: {vs_after_step2}")

for i, s in enumerate(step3):
    token_name = "WETH" if s['token_in'] == weth_addr else "osETH"
    print(f"\n  Step3 Swap {i} BEFORE: bW={bW}, bO={bO}, vs={total_supply - bBPT}")
    if s['token_in'] == weth_addr:
        bW += s['amount_in']
    elif s['token_in'] == oseth_addr:
        bO += s['amount_in']
    bBPT -= s['amount_out']  # BPT leaves pool
    print(f"  Step3 Swap {i} AFTER:  bW={bW}, bO={bO}, vs={total_supply - bBPT}")

print(f"\nFinal state:")
print(f"  WETH:  {bW}")
print(f"  osETH: {bO}")
print(f"  registeredBPT: {bBPT}")
print(f"  virtualSupply: {total_supply - bBPT}")

# === Step 1 detailed tracking ===
print(f"\n=== Step 1 detailed (BPT sold per swap, running virtualSupply) ===")
cum_bpt = 0
vs = init_virtual_supply
bW_track = init_weth
bO_track = init_oseth
for i, s in enumerate(step1):
    bpt_in = s['amount_in']
    cum_bpt += bpt_in
    vs -= bpt_in
    token_name = "WETH" if s['token_out'] == weth_addr else "osETH"
    token_out = s['amount_out']
    if s['token_out'] == weth_addr:
        bW_track -= token_out
    else:
        bO_track -= token_out
    if i < 5 or i >= 17:
        print(f"  Swap {i:2d}: BPT_in={bpt_in:>30d} -> {token_name} out={token_out:>30d}  cumBPT={cum_bpt}  vs={vs}  balW={bW_track} balO={bO_track}")

# === Show all 121 swaps in order with type ===
print(f"\n=== First/last swap ordering (showing type transitions) ===")
for i, s in enumerate(swaps):
    if s['token_in'] == bpt_addr:
        stype = "EXIT"
    elif s['token_out'] == bpt_addr:
        stype = "JOIN"
    else:
        stype = "SWAP"
    if i < 25 or i > 108:
        tok_in = "BPT" if s['token_in'] == bpt_addr else ("WETH" if s['token_in'] == weth_addr else "osETH")
        tok_out = "BPT" if s['token_out'] == bpt_addr else ("WETH" if s['token_out'] == weth_addr else "osETH")
        print(f"  [{i:3d}] {stype} {tok_in}->{tok_out} in={s['amount_in']} out={s['amount_out']}")

# === Decode PoolBalanceChanged events ===
# keccak256("PoolBalanceChanged(bytes32,address,address[],int256[],uint256[])")
pbc_sig = "0xe5ce249087ce04f05a957571b0d4513bc76ba319ca2e3e2bee0f8b33a7f41089"
print(f"\n=== PoolBalanceChanged events for this pool ===")
for log in receipt['logs']:
    if log['address'].lower() == vault and log['topics'][0] == pbc_sig:
        pool = log['topics'][1]
        if pool.lower() == pool_id.lower():
            data = log['data'][2:]
            # Decode: offset_tokens, offset_deltas, offset_protocolFees
            # then each array: length, values
            # Simpler: just print raw data length and first few words
            words = [data[i:i+64] for i in range(0, len(data), 64)]
            print(f"  PoolBalanceChanged event, {len(words)} data words")
            # The deltas are int256 values (signed)
            # Layout: offset_tokens(0), offset_deltas(1), offset_protocolFees(2)
            # tokens array at offset: length, addr0, addr1, addr2
            # deltas array: length, delta0, delta1, delta2
            off_deltas = int(words[1], 16) // 32  # word offset for deltas
            n_deltas = int(words[off_deltas], 16)
            deltas = []
            for di in range(n_deltas):
                raw = int(words[off_deltas + 1 + di], 16)
                if raw >= 2**255:
                    raw -= 2**256
                deltas.append(raw)
            print(f"  Deltas: {deltas}")
            print(f"    WETH delta:  {deltas[0]}")
            print(f"    BPT delta:   {deltas[1]}")
            print(f"    osETH delta: {deltas[2]}")


import json, sys, subprocess

result = subprocess.run([
    "cast", "receipt",
    "0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742",
    "--rpc-url", "https://ethereum-rpc.publicnode.com",
    "--json"
], capture_output=True, text=True)

data = json.loads(result.stdout)
logs = data['logs']

transfer_topic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
swap_topic = '0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b'

pool = '0xdacf5fa19b1f720111609043ac67a9818262850c'
vault = '0xba12222222228d8ba445958a75a0704d566bf2c8'
attacker = '0x5ae5223b41a4e3d1b3f65c99d7019ad3e0f4a068'  # attacker contract

zero = '0x0000000000000000000000000000000000000000'

print("=== BPT Transfer events ===")
bpt_transfers = []
for i, log in enumerate(logs):
    addr = log['address'].lower()
    topics = log['topics']
    if addr == pool and topics[0] == transfer_topic:
        frm = '0x' + topics[1][26:]
        to = '0x' + topics[2][26:]
        amount = int(log['data'], 16)
        bpt_transfers.append((i, frm, to, amount))

# Categorize
total_minted = 0  # from zero address
total_burned = 0  # to zero address
vault_to_attacker = 0
attacker_to_vault = 0

for idx, frm, to, amount in bpt_transfers:
    if frm == zero:
        total_minted += amount
        print(f"  MINT:     log {idx:3d}, amount={amount}")
    elif to == zero:
        total_burned += amount
        print(f"  BURN:     log {idx:3d}, amount={amount}")
    elif frm.startswith(vault[:10]) and to.startswith(attacker[:10]):
        vault_to_attacker += amount
        print(f"  V->ATK:   log {idx:3d}, amount={amount}")
    elif frm.startswith(attacker[:10]) and to.startswith(vault[:10]):
        attacker_to_vault += amount
        print(f"  ATK->V:   log {idx:3d}, amount={amount}")
    else:
        print(f"  OTHER:    log {idx:3d}, from={frm[:12]}... to={to[:12]}... amount={amount}")

print(f"\n=== Summary ===")
print(f"Total BPT transfer events: {len(bpt_transfers)}")
print(f"Total BPT minted (from zero):  {total_minted}")
print(f"Total BPT burned (to zero):    {total_burned}")
print(f"Net (minted - burned):         {total_minted - total_burned}")
print(f"Vault -> Attacker:             {vault_to_attacker}")
print(f"Attacker -> Vault:             {attacker_to_vault}")
print(f"Net attacker (received-sent):  {vault_to_attacker - attacker_to_vault}")

# Also look at Swap events to find BPT amounts in/out
print("\n=== Swap events involving BPT (pool token) ===")
# Swap event: poolId, tokenIn, tokenOut, amountIn, amountOut
# We want swaps where tokenIn or tokenOut is BPT
bpt_in_total = 0
bpt_out_total = 0
swap_count = 0
for i, log in enumerate(logs):
    addr = log['address'].lower()
    topics = log['topics']
    if addr == vault and topics[0] == swap_topic:
        # topics[1] = poolId, topics[2] = tokenIn, topics[3] = tokenOut
        token_in = '0x' + topics[2][26:]
        token_out = '0x' + topics[3][26:]
        # data = amountIn (32 bytes) + amountOut (32 bytes)
        d = log['data'][2:]  # strip 0x
        amount_in = int(d[:64], 16)
        amount_out = int(d[64:128], 16)
        
        if token_in == pool:
            bpt_in_total += amount_in
            swap_count += 1
        elif token_out == pool:
            bpt_out_total += amount_out
            swap_count += 1

print(f"Total swaps involving BPT: {swap_count}")
print(f"Total BPT as tokenIn (exits/burns):  {bpt_in_total}")
print(f"Total BPT as tokenOut (joins/mints): {bpt_out_total}")
print(f"Net BPT flow (in - out):             {bpt_in_total - bpt_out_total}")

# Actual supply comparison
supply_fork = 11847097352927601082261
supply_attack = 11893127211037251149120
print(f"\n=== Actual Supply ===")
print(f"Fork block 23717396:   {supply_fork}")
print(f"Attack block 23717397: {supply_attack}")
print(f"Difference:            {supply_attack - supply_fork}")
print(f"Ratio (attack/fork):   {supply_attack / supply_fork:.10f}")


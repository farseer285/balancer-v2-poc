import json, sys

data = json.load(sys.stdin)
swap_topic = '0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b'
pool_id_hex = '0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635'
WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
OSETH = '0xf1c9acdc66974dfb6decb12aa385b9cd01190e38'
BPT = '0xdacf5fa19b1f720111609043ac67a9818262850c'
vault = '0xba12222222228d8ba445958a75a0704d566bf2c8'
names = {WETH: 'WETH', OSETH: 'osETH', BPT: 'BPT'}

swaps = []
for log in data['logs']:
    if log['address'].lower() == vault and len(log['topics']) >= 4 and log['topics'][0] == swap_topic:
        pid = log['topics'][1]
        if pid.lower() == pool_id_hex.lower():
            tin_addr = '0x' + log['topics'][2][26:]
            tout_addr = '0x' + log['topics'][3][26:]
            raw = log['data'][2:]
            amountIn = int(raw[:64], 16)
            amountOut = int(raw[64:128], 16)
            tin = names.get(tin_addr.lower(), tin_addr[:10])
            tout = names.get(tout_addr.lower(), tout_addr[:10])
            swaps.append((tin, tout, amountIn, amountOut))

# Phase 1: BPT -> token (swaps where tokenIn=BPT)
# Phase 2: token cycling (WETH<->osETH)
# Phase 3: token -> BPT (swaps where tokenOut=BPT)
p1_bpt_in = 0; p1_weth_out = 0; p1_oseth_out = 0; p1_count = 0
p2_weth_in = 0; p2_weth_out = 0; p2_oseth_in = 0; p2_oseth_out = 0; p2_count = 0
p3_weth_in = 0; p3_oseth_in = 0; p3_bpt_out = 0; p3_count = 0

phase = 1
for i, (tin, tout, ain, aout) in enumerate(swaps):
    if phase == 1 and tin == 'BPT':
        p1_bpt_in += ain
        if tout == 'WETH': p1_weth_out += aout
        elif tout == 'osETH': p1_oseth_out += aout
        p1_count += 1
    elif phase <= 2 and tin != 'BPT' and tout != 'BPT':
        phase = 2
        if tin == 'WETH': p2_weth_in += ain
        elif tin == 'osETH': p2_oseth_in += ain
        if tout == 'WETH': p2_weth_out += aout
        elif tout == 'osETH': p2_oseth_out += aout
        p2_count += 1
    elif tout == 'BPT':
        phase = 3
        if tin == 'WETH': p3_weth_in += ain
        elif tin == 'osETH': p3_oseth_in += ain
        p3_bpt_out += aout
        p3_count += 1
    else:
        phase = 2
        if tin == 'WETH': p2_weth_in += ain
        elif tin == 'osETH': p2_oseth_in += ain
        if tout == 'WETH': p2_weth_out += aout
        elif tout == 'osETH': p2_oseth_out += aout
        p2_count += 1

print(f'=== Phase 1: BPT -> Token Extraction ({p1_count} swaps) ===')
print(f'BPT spent:      {p1_bpt_in} ({p1_bpt_in/1e18:.6f})')
print(f'WETH received:  {p1_weth_out} ({p1_weth_out/1e18:.6f})')
print(f'osETH received: {p1_oseth_out} ({p1_oseth_out/1e18:.6f})')
print(f'Total tokens:   {p1_weth_out + p1_oseth_out} ({(p1_weth_out + p1_oseth_out)/1e18:.6f})')

print(f'\n=== Phase 2: Token Cycling ({p2_count} swaps, {p2_count//4} rounds) ===')
print(f'WETH in:  {p2_weth_in}  WETH out:  {p2_weth_out}')
print(f'osETH in: {p2_oseth_in}  osETH out: {p2_oseth_out}')
p2_net_weth = p2_weth_out - p2_weth_in
p2_net_oseth = p2_oseth_out - p2_oseth_in
print(f'Net WETH:  {p2_net_weth}')
print(f'Net osETH: {p2_net_oseth}')
print(f'Cycling cost (tokens consumed): {-(p2_net_weth + p2_net_oseth)}')

print(f'\n=== Phase 3: Token -> BPT Repurchase ({p3_count} swaps) ===')
print(f'WETH spent:     {p3_weth_in} ({p3_weth_in/1e18:.6f})')
print(f'osETH spent:    {p3_oseth_in} ({p3_oseth_in/1e18:.6f})')
print(f'Total cost:     {p3_weth_in + p3_oseth_in} ({(p3_weth_in + p3_oseth_in)/1e18:.6f})')
print(f'BPT received:   {p3_bpt_out} ({p3_bpt_out/1e18:.6f})')

print(f'\n=== PROFIT CALCULATION ===')
total_tokens = p1_weth_out + p1_oseth_out
cycling_cost = -(p2_net_weth + p2_net_oseth)
repayment = p3_weth_in + p3_oseth_in
profit = total_tokens - cycling_cost - repayment
print(f'Tokens extracted (Step 1): {total_tokens} ({total_tokens/1e18:.6f})')
print(f'Cycling cost (Step 2):     {cycling_cost} ({cycling_cost/1e18:.6f})')
print(f'Repayment cost (Step 3):   {repayment} ({repayment/1e18:.6f})')
print(f'NET PROFIT:                {profit} ({profit/1e18:.6f})')

print(f'\n=== BPT BALANCE ===')
print(f'BPT spent in Step 1:    {p1_bpt_in} ({p1_bpt_in/1e18:.6f})')
print(f'BPT bought in Step 3:   {p3_bpt_out} ({p3_bpt_out/1e18:.6f})')
print(f'Net BPT delta:          {p3_bpt_out - p1_bpt_in} ({(p3_bpt_out - p1_bpt_in)/1e18:.6f})')


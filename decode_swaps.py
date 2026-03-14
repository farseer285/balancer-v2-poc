import json, sys

data = json.load(sys.stdin)
swap_topic = '0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b'
pool_id_hex = '0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635'
WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
OSETH = '0xf1c9acdc66974dfb6decb12aa385b9cd01190e38'
BPT = '0xdacf5fa19b1f720111609043ac67a9818262850c'
vault = '0xba12222222228d8ba445958a75a0704d566bf2c8'

names = {WETH: 'WETH', OSETH: 'osETH', BPT: 'BPT'}

count = 0
total_bpt_in = 0
total_weth_in = 0
total_oseth_in = 0
total_weth_out = 0
total_oseth_out = 0
total_bpt_out = 0

for log in data['logs']:
    if log['address'].lower() == vault and len(log['topics']) >= 4 and log['topics'][0] == swap_topic:
        pid = log['topics'][1]
        if pid.lower() == pool_id_hex.lower():
            token_in_addr = '0x' + log['topics'][2][26:]
            token_out_addr = '0x' + log['topics'][3][26:]
            raw = log['data'][2:]
            amountIn = int(raw[:64], 16)
            amountOut = int(raw[64:128], 16)

            tin = names.get(token_in_addr.lower(), token_in_addr[:10])
            tout = names.get(token_out_addr.lower(), token_out_addr[:10])
            count += 1

            # Track totals
            if tin == 'BPT': total_bpt_in += amountIn
            elif tin == 'WETH': total_weth_in += amountIn
            elif tin == 'osETH': total_oseth_in += amountIn
            if tout == 'BPT': total_bpt_out += amountOut
            elif tout == 'WETH': total_weth_out += amountOut
            elif tout == 'osETH': total_oseth_out += amountOut

            print(f'Swap {count:3d}: {tin:5s} -> {tout:5s}  in={amountIn:>30d}  out={amountOut:>30d}')

print(f'\nTotal swaps in Pool 1: {count}')
print(f'\n=== TOTALS ===')
print(f'BPT in:    {total_bpt_in} ({total_bpt_in/1e18:.6f})')
print(f'BPT out:   {total_bpt_out} ({total_bpt_out/1e18:.6f})')
print(f'WETH in:   {total_weth_in} ({total_weth_in/1e18:.6f})')
print(f'WETH out:  {total_weth_out} ({total_weth_out/1e18:.6f})')
print(f'osETH in:  {total_oseth_in} ({total_oseth_in/1e18:.6f})')
print(f'osETH out: {total_oseth_out} ({total_oseth_out/1e18:.6f})')
print(f'\nNet BPT:   {total_bpt_in - total_bpt_out} ({(total_bpt_in - total_bpt_out)/1e18:.6f})')
print(f'Net WETH:  {total_weth_out - total_weth_in} ({(total_weth_out - total_weth_in)/1e18:.6f})')
print(f'Net osETH: {total_oseth_out - total_oseth_in} ({(total_oseth_out - total_oseth_in)/1e18:.6f})')


#!/usr/bin/env python3
import json, sys

data = json.load(sys.stdin)
logs = data['logs']

swap_topic = '0x2170c741c41531aec20e7c107c24eecfdd15e69c9bb0a8dd37b1840b9e0b207b'
ibc_topic = '0x18e1ea4139e68413d7d08aa752e71568e36b2c5bf940893314c2c5b01eaa0c42'
pool1_id = '0xdacf5fa19b1f720111609043ac67a9818262850c000000000000000000000635'

weth = 'c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
oseth = 'f1c9acdc66974dfb6decb12aa385b9cd01190e38'
bpt = 'dacf5fa19b1f720111609043ac67a9818262850c'

def token_name(addr):
    a = addr.lower()
    if weth in a: return 'WETH'
    if oseth in a: return 'osETH'
    if bpt in a: return 'BPT'
    return addr[-8:]

pool1_swaps = []
ibc_events = []

for log in logs:
    topics = log['topics']
    if topics[0] == swap_topic:
        if topics[1] == pool1_id:
            token_in = '0x' + topics[2][26:]
            token_out = '0x' + topics[3][26:]
            d = log['data'][2:]
            amount_in = int(d[:64], 16)
            amount_out = int(d[64:128], 16)
            pool1_swaps.append((token_in, token_out, amount_in, amount_out))
    elif topics[0] == ibc_topic:
        user = '0x' + topics[1][26:]
        token = '0x' + topics[2][26:]
        d = log['data'][2:]
        delta = int(d[:64], 16)
        if delta >= 2**255:
            delta -= 2**256
        ibc_events.append((user, token, delta))

print(f'Total Pool 1 Swap events: {len(pool1_swaps)}')
print('First 5:')
for s in pool1_swaps[:5]:
    print(f'  {token_name(s[0])} -> {token_name(s[1])}: in={s[2]} out={s[3]}')
print('Last 5:')
for s in pool1_swaps[-5:]:
    print(f'  {token_name(s[0])} -> {token_name(s[1])}: in={s[2]} out={s[3]}')

# Net deltas: amount_in = user sends to pool (positive), amount_out = user receives (negative)
net = {}
for s in pool1_swaps:
    tin = s[0].lower()
    tout = s[1].lower()
    net[tin] = net.get(tin, 0) + s[2]
    net[tout] = net.get(tout, 0) - s[3]

print(f'\n=== Pool 1 NET DELTAS (positive=user pays, negative=user receives) ===')
for addr, val in net.items():
    print(f'{token_name(addr)}: {val} ({val/1e18:.4f})')

print(f'\n=== InternalBalanceChanged events ===')
for e in ibc_events:
    print(f'{token_name(e[1])}: user={e[0][-8:]} delta={e[2]} ({e[2]/1e18:.4f})')


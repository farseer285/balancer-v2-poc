balance_weth = 961094652498916958834
balance_oseth = 944397497721693800385

for target in [67000, 94000]:
    remain = balance_weth
    steps = 0
    while remain > target:
        excess = remain - target
        amount = excess * 99 // 100
        if amount == 0:
            steps += 1
            break
        remain -= amount
        steps += 1
    weth_steps = steps
    print(f'target={target}: Step1 WETH needs {steps} swaps, final={remain}')
    
    remain = balance_oseth
    steps = 0
    while remain > target:
        excess = remain - target
        amount = excess * 99 // 100
        if amount == 0:
            steps += 1
            break
        remain -= amount
        steps += 1
    oseth_steps = steps
    print(f'target={target}: Step1 osETH needs {steps} swaps, final={remain}')
    
    total_step1 = weth_steps + oseth_steps
    total = total_step1 + 30 * 3 + 9
    print(f'target={target}: Total swaps = {total_step1} + 90 + 9 = {total}')
    print()


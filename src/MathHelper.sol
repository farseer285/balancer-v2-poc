// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/// @title  MathHelper
/// @notice Reconstructed from on-chain bytecode disassembly (selector 0x524c9e20).
///         Implements a Balancer V2 StableMath-style _calcInGivenOut helper
///         guarded by a tx.origin allow-list of two storage admins.
/// @dev    Error codes follow Balancer V2 convention:
///           BAL#000  ADD_OVERFLOW
///           BAL#001  SUB_OVERFLOW
///           BAL#003  MUL_OVERFLOW
///           BAL#004  ZERO_DIVISION
///           BAL#321  STABLE_INVARIANT_DIDNT_CONVERGE   (= 0x141)
///           BAL#322  STABLE_GET_BALANCE_DIDNT_CONVERGE (= 0x142)
contract MathHelper {
    // ---------------------------------------------------------------------
    // Storage layout (matches AUTH CHECK 0x0059-0x00bd: SLOAD slot 0 / 1)
    // ---------------------------------------------------------------------
    address public admin0; // slot 0
    address public admin1; // slot 1

    // ---------------------------------------------------------------------
    // Constants  (matches PUSH8 0x0de0b6b3a7640000 == 1e18 in the bytecode)
    // ---------------------------------------------------------------------
    uint256 internal constant ONE           = 1e18;  // FixedPoint.ONE
    uint256 internal constant AMP_PRECISION = 1e3;   // StableMath constant
    uint256 internal constant MAX_LOOP      = 255;   // Newton iters cap

    constructor(address _admin0, address _admin1) {
        admin0 = _admin0;
        admin1 = _admin1;
    }

    // =====================================================================
    //  Public entry point (selector 0x524c9e20)
    //
    //  Calldata layout (head, 7 slots) decoded from the on-chain attack tx
    //  0x6ed0...9742 against contract 0x679B...381e at block 23717397:
    //      0  uint256[] balances        (offset 0xe0)
    //      1  uint256[] scalingFactors  (offset 0x140)
    //      2  uint256   tokenIndexIn
    //      3  uint256   tokenIndexOut
    //      4  uint256   tokenAmountOut
    //      5  uint256   amplificationParameter
    //      6  uint256   swapFeePercentage
    //
    //  Return value is the *input* `balances` array, modified in-place to
    //  match the on-chain bytecode memory semantics (the bytecode never
    //  allocates a new array for the result; it mutates the decoded calldata
    //  copy and returns its pointer via SWAP12/SWAP13 at 0x0287-0x0296):
    //      balances[tokenIndexIn]  += rawAmountInWithFee
    //      balances[tokenIndexOut] -= tokenAmountOut
    //
    //  Steps mirror the disassembly:
    //  1. upscale  adjusted[i] = balances[i] * scalingFactors[i] / 1e18
    //  2. manipulationAmount   = tokenAmountOut * scalingFactors[idxOut] / 1e18
    //  3. invariant            = _calculateInvariantRatio(...)        @0x0297
    //  4. newBalInUpscaled     = _updateBalance(...)                  @0x03fa
    //  5. amountInUpscaled     = newBalInUpscaled - adjusted[idxIn]
    //     rawAmountIn          = (amountInUpscaled + sf[idxIn] - 1) / sf[idxIn]
    //                                                       (i.e. divUp)
    //     rawAmountInWithFee   = (rawAmountIn * 1e18 + (1e18 - swapFee) - 1)
    //                            / (1e18 - swapFee)         (i.e. divUp by complement)
    //     newBalances[idxIn]   = balances[idxIn] + rawAmountInWithFee
    //     newBalances[idxOut]  = balances[idxOut] - tokenAmountOut
    // =====================================================================
    function swapGivenOut(
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        uint256          tokenIndexIn,
        uint256          tokenIndexOut,
        uint256          tokenAmountOut,
        uint256          amplificationParameter,
        uint256          swapFeePercentage
    ) external view returns (uint256[] memory) {

        // -------------------- AUTH CHECK (0x0059-0x00bd) ----------------
        require(
            tx.origin == admin0 || tx.origin == admin1,
            "Ownable: caller is not the owner"
        );

        // -------------------- STEP 1 (0x00be-0x0169) --------------------
        uint256 n = balances.length;
        uint256[] memory adjusted = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            adjusted[i] = _div(_mul(balances[i], scalingFactors[i]), ONE);
        }

        // -------------------- STEP 2 (0x016a-0x01a1) --------------------
        uint256 manipulationAmount =
            _div(_mul(tokenAmountOut, scalingFactors[tokenIndexOut]), ONE);

        // -------------------- STEP 3 (0x01a2-0x01b3) --------------------
        uint256 invariant =
            _calculateInvariantRatio(amplificationParameter, adjusted);

        // -------------------- STEP 4 (0x01b4-0x01c3) --------------------
        // _updateBalance already returns the *upscaled* amountIn (with +1),
        // matching Balancer V2 StableMath._calcInGivenOut.
        uint256 amountInUpscaled = _updateBalance(
            amplificationParameter,
            adjusted,
            tokenIndexIn,
            tokenIndexOut,
            manipulationAmount,
            invariant
        );

        // -------------------- STEP 5 (0x01c4-0x0296) --------------------
        // 1) downscale-up to raw       = divUp(amountInUpscaled, sf[idxIn])
        // 2) gross-up by swap fee      = divUp(raw * 1e18, 1e18 - swapFee)
        // 3) mutate `balances` in-place and return its pointer
        //      balances[idxIn]  += rawWithFee
        //      balances[idxOut] -= tokenAmountOut
        // FixedPoint.divUp: inflate numerator by 1e18 before divUp so the
        // downscale itself is bit-perfect (matches bytecode at 0x01f8 MUL 1e18).
        uint256 rawAmountIn        =
            _divUp(_mul(amountInUpscaled, ONE), scalingFactors[tokenIndexIn]);
        uint256 rawAmountInWithFee =
            _divUp(_mul(rawAmountIn, ONE), _sub(ONE, swapFeePercentage));

        balances[tokenIndexIn]  = _add(balances[tokenIndexIn], rawAmountInWithFee);
        balances[tokenIndexOut] = _sub(balances[tokenIndexOut], tokenAmountOut);
        return balances;
    }

    // =====================================================================
    //  func_0297  _calculateInvariant  (Newton-Raphson outer, ≤255)
    //
    //    sum   = Σ balances[i]
    //    if sum == 0  → return 0
    //    D_P    = invariant
    //    for j in 0..n-1:  D_P = (D_P * invariant) / (balances[j] * n)
    //    invariant <- ( ( ampTotal*sum/AMP_PRECISION + D_P*n ) * invariant )
    //                 / ( (ampTotal-AMP_PRECISION)*invariant/AMP_PRECISION
    //                     + (n+1) * D_P )
    //    converge when |Δ| ≤ 1   else revert BAL#321
    // =====================================================================
    function _calculateInvariantRatio(uint256 amp, uint256[] memory balances)
        internal pure returns (uint256)
    {
        uint256 sum = 0;
        uint256 n   = balances.length;
        for (uint256 i = 0; i < n; i++) {
            sum = _add(sum, balances[i]);
        }
        if (sum == 0) return 0;

        uint256 invariant     = sum;
        uint256 ampTimesTotal = _mul(amp, n);

        for (uint256 it = 0; it < MAX_LOOP; it++) {
            uint256 D_P = invariant;
            for (uint256 j = 0; j < n; j++) {
                D_P = _div(_mul(D_P, invariant), _mul(balances[j], n));
            }

            uint256 prev = invariant;
            invariant = _div(
                _mul(
                    _add(
                        _div(_mul(ampTimesTotal, sum), AMP_PRECISION),
                        _mul(D_P, n)
                    ),
                    invariant
                ),
                _add(
                    _div(_mul(_sub(ampTimesTotal, AMP_PRECISION), invariant), AMP_PRECISION),
                    _mul(_add(n, 1), D_P)
                )
            );

            if (invariant > prev) {
                if (invariant - prev <= 1) return invariant;
            } else if (prev - invariant <= 1) {
                return invariant;
            }
        }
        _revertBAL(0x141); // BAL#321
    }

    // =====================================================================
    //  func_03fa  _updateBalance       (== Balancer V2 StableMath._calcInGivenOut
    //                                    after the indexOut decrement+restore)
    //
    //    balances[indexOut] -= amountOut           (in-place, then restored)
    //    finalBalIn = _getTokenBalanceGivenInvariantAndAllOtherBalances(...)
    //    balances[indexOut] += amountOut           (restore)
    //    return _add(_sub(finalBalIn, balances[indexIn]), 1)   ; +1 rounding
    // =====================================================================
    function _updateBalance(
        uint256          amp,
        uint256[] memory balances,
        uint256          indexIn,
        uint256          indexOut,
        uint256          amountOut,
        uint256          invariant
    ) internal pure returns (uint256 amountInUpscaled) {
        balances[indexOut] = _sub(balances[indexOut], amountOut);

        uint256 finalBalanceIn = _getTokenBalanceGivenInvariantAndAllOtherBalances(
            amp, balances, invariant, indexIn
        );

        balances[indexOut] = _add(balances[indexOut], amountOut);

        amountInUpscaled = _add(_sub(finalBalanceIn, balances[indexIn]), 1);
    }

    // =====================================================================
    //  func_054f  _getTokenBalanceGivenInvariantAndAllOtherBalances
    //             (Newton-Raphson inner, ≤255)
    //
    //    Solves the quadratic
    //         tokenBalance = (tokenBalance^2 + c)
    //                        / (2·tokenBalance + b - invariant)
    //    converge when |Δ| ≤ 1   else revert BAL#322
    // =====================================================================
    function _getTokenBalanceGivenInvariantAndAllOtherBalances(
        uint256          amp,
        uint256[] memory balances,
        uint256          invariant,
        uint256          tokenIndex
    ) internal pure returns (uint256) {
        uint256 ampTimesTotal = _mul(amp, balances.length);
        uint256 sum = balances[0];
        uint256 P_D = _mul(balances[0], balances.length);
        for (uint256 j = 1; j < balances.length; j++) {
            P_D = _div(_mul(_mul(P_D, balances[j]), balances.length), invariant);
            sum = _add(sum, balances[j]);
        }
        sum = _sub(sum, balances[tokenIndex]);

        uint256 inv2 = _mul(invariant, invariant);
        // c = (inv2 / (ampTimesTotal · P_D)) · AMP_PRECISION · balances[tokenIndex]
        uint256 c = _mul(
            _mul(_divUp(inv2, _mul(ampTimesTotal, P_D)), AMP_PRECISION),
            balances[tokenIndex]
        );
        uint256 b = _add(sum, _mul(_div(invariant, ampTimesTotal), AMP_PRECISION));

        uint256 prevTokenBalance;
        uint256 tokenBalance = _divUp(_add(inv2, c), _add(invariant, b));

        for (uint256 i = 0; i < MAX_LOOP; i++) {
            prevTokenBalance = tokenBalance;
            tokenBalance = _divUp(
                _add(_mul(tokenBalance, tokenBalance), c),
                _sub(_add(_mul(tokenBalance, 2), b), invariant)
            );
            if (tokenBalance > prevTokenBalance) {
                if (tokenBalance - prevTokenBalance <= 1) return tokenBalance;
            } else if (prevTokenBalance - tokenBalance <= 1) {
                return tokenBalance;
            }
        }
        _revertBAL(0x142); // BAL#322
    }

    // =====================================================================
    //  func_04af  _add (overflow guard, BAL#000)
    // =====================================================================
    function _add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        if (c < a) _revertBAL(0);
    }

    // =====================================================================
    //  func_0538  _sub (underflow guard, BAL#001)
    // =====================================================================
    function _sub(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b > a) _revertBAL(1);
        return a - b;
    }

    // =====================================================================
    //  func_04c8  _mul (overflow guard, BAL#003)
    //  Note: bytecode performs raw a*b without /1e18, so this is integer mul,
    //  not Balancer's FixedPoint.mulDown.
    // =====================================================================
    function _mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a * b;
        if (a != 0 && c / a != b) _revertBAL(3);
    }

    // =====================================================================
    //  func_04ec  _div (zero-div guard, BAL#004)
    //  Note: bytecode is plain DIV (round-down) with only zero-divisor check.
    // =====================================================================
    function _div(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) _revertBAL(4);
        return a / b;
    }

    // =====================================================================
    //  _divUp  (round-up division, used inside the inner Newton-Raphson)
    // =====================================================================
    function _divUp(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) _revertBAL(4);
        if (a == 0) return 0;
        return ((a - 1) / b) + 1;
    }

    // =====================================================================
    //  func_050c  _revertBAL
    //  Reverts with the ABI-encoded string "BAL#" || decimal(code).
    //  In bytecode the prefix is the constant 0x42414c00…00 ("BAL\0…").
    // =====================================================================
    function _revertBAL(uint256 code) internal pure {
        // 3-digit zero-padded decimal, matching Balancer's _revert helper.
        bytes memory b = new bytes(7);
        b[0] = 0x42; // 'B'
        b[1] = 0x41; // 'A'
        b[2] = 0x4c; // 'L'
        b[3] = 0x23; // '#'
        b[4] = bytes1(uint8(48 + ((code / 100) % 10)));
        b[5] = bytes1(uint8(48 + ((code /  10) % 10)));
        b[6] = bytes1(uint8(48 +  (code        % 10)));
        revert(string(b));
    }
}

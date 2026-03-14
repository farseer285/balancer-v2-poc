// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {FixedPoint} from "./FixedPoint.sol";
import {Math} from "./Math.sol";
import {console} from "forge-std/Console.sol";

library StableMath {
    using FixedPoint for uint256;

    uint256 internal constant _AMP_PRECISION = 1e3;

    function _calculateInvariant(uint256 amplificationParameter, uint256[] memory balances)
        internal
        pure
        returns (uint256)
    {
        /**********************************************************************************************
        // invariant                                                                                 //
        // D = invariant                                                  D^(n+1)                    //
        // A = amplification coefficient      A  n^n S + D = A D n^n + -----------                   //
        // S = sum of balances                                             n^n P                     //
        // P = product of balances                                                                   //
        // n = number of tokens                                                                      //
        **********************************************************************************************/

        // Always round down, to match Vyper's arithmetic (which always truncates).
        // for (uint256 i = 0; i < balances.length; i++) {
        //     console.log("balance [", i, "] in _calculateInvariant", balances[i]);
        // }

        uint256 sum = 0; // S in the Curve version
        uint256 numTokens = balances.length;
        for (uint256 i = 0; i < numTokens; i++) {
            sum += balances[i];
        }
        if (sum == 0) {
            return 0;
        }

        uint256 prevInvariant; // Dprev in the Curve version
        uint256 invariant = sum; // D in the Curve version
        uint256 ampTimesTotal = amplificationParameter * numTokens; // Ann in the Curve version

        for (uint256 i = 0; i < 30; i++) {
            uint256 D_P = invariant;

            for (uint256 j = 0; j < numTokens; j++) {
                // (D_P * invariant) / (balances[j] * numTokens)
                D_P = Math.divDown(Math.mul(D_P, invariant), Math.mul(balances[j], numTokens));
            }

            prevInvariant = invariant;

            invariant = Math.divDown(
                Math.mul(
                    // (ampTimesTotal * sum) / AMP_PRECISION + D_P * numTokens
                    (Math.divDown(Math.mul(ampTimesTotal, sum), _AMP_PRECISION) + (Math.mul(D_P, numTokens))),
                    invariant
                ),
                // ((ampTimesTotal - _AMP_PRECISION) * invariant) / _AMP_PRECISION + (numTokens + 1) * D_P
                (Math.divDown(Math.mul((ampTimesTotal - _AMP_PRECISION), invariant), _AMP_PRECISION)
                        + (Math.mul((numTokens + 1), D_P)))
            );

            // console.log("prevInvariant in iteration ", i, " is ", prevInvariant);
            // console.log("invariant in iteration ", i, " is ", invariant);

            if (invariant > prevInvariant) {
                if (invariant - prevInvariant <= 1) {
                    return invariant;
                }
            } else if (prevInvariant - invariant <= 1) {
                return invariant;
            }
        }

        revert("STABLE_INVARIANT_DIDNT_CONVERGE");
    }

    // Computes how many tokens must be sent to a pool if `tokenAmountOut` are sent given the
    // current balances, using the Newton-Raphson approximation.
    // The amplification parameter equals: A n^(n-1)
    function _calcInGivenOut(
        uint256 amplificationParameter,
        uint256[] memory balances,
        uint256 tokenIndexIn,
        uint256 tokenIndexOut,
        uint256 tokenAmountOut,
        uint256 invariant
    ) internal pure returns (uint256) {
        /**************************************************************************************************************
        // inGivenOut token x for y - polynomial equation to solve                                                   //
        // ax = amount in to calculate                                                                               //
        // bx = balance token in                                                                                     //
        // x = bx + ax (finalBalanceIn)                                                                              //
        // D = invariant                                                D                     D^(n+1)                //
        // A = amplification coefficient               x^2 + ( S + ----------  - D) * x -  ------------- = 0         //
        // n = number of tokens                                     (A * n^n)               A * n^2n * P             //
        // S = sum of final balances but x                                                                           //
        // P = product of final balances but x                                                                       //
        **************************************************************************************************************/
        // Amount in, so we round up overall.

        balances[tokenIndexOut] = balances[tokenIndexOut] - tokenAmountOut;

        uint256 finalBalanceIn = _getTokenBalanceGivenInvariantAndAllOtherBalances(
            amplificationParameter, balances, invariant, tokenIndexIn
        );

        // No need to use checked arithmetic since `tokenAmountOut` was actually subtracted from the same balance right
        // before calling `_getTokenBalanceGivenInvariantAndAllOtherBalances` which doesn't alter the balances array.
        balances[tokenIndexOut] = balances[tokenIndexOut] + tokenAmountOut;

        return finalBalanceIn - balances[tokenIndexIn] + 1;
    }

    // Computes how much BPT must be burned to receive exact `amountsOut` tokens.
    // This is the real Balancer _calcBptInGivenExactTokensOut with internal fee handling.
    function _calcBptInGivenExactTokensOut(
        uint256 amp,
        uint256[] memory balances,
        uint256[] memory amountsOut,
        uint256 bptTotalSupply,
        uint256 currentInvariant,
        uint256 swapFeePercentage
    ) internal pure returns (uint256) {
        // BPT in, so we round up overall.

        // First loop calculates the sum of all token balances
        uint256 sumBalances = 0;
        for (uint256 i = 0; i < balances.length; i++) {
            sumBalances = sumBalances + balances[i];
        }

        // Calculate the weighted balance ratio without considering fees
        uint256[] memory balanceRatiosWithoutFee = new uint256[](amountsOut.length);
        uint256 invariantRatioWithoutFees = 0;
        for (uint256 i = 0; i < balances.length; i++) {
            uint256 currentWeight = FixedPoint.divUp(balances[i], sumBalances);
            balanceRatiosWithoutFee[i] = (balances[i] - amountsOut[i]).divUp(balances[i]);
            invariantRatioWithoutFees = invariantRatioWithoutFees + balanceRatiosWithoutFee[i].mulUp(currentWeight);
        }

        // Second loop calculates new amounts, taking into account the fee on the percentage excess
        uint256[] memory newBalances = new uint256[](balances.length);
        for (uint256 i = 0; i < balances.length; i++) {
            uint256 amountOutWithFee;
            if (invariantRatioWithoutFees > balanceRatiosWithoutFee[i]) {
                uint256 nonTaxableAmount = balances[i].mulDown(invariantRatioWithoutFees.complement());
                uint256 taxableAmount = amountsOut[i] - nonTaxableAmount;
                amountOutWithFee = nonTaxableAmount + taxableAmount.divUp(FixedPoint.ONE - swapFeePercentage);
            } else {
                amountOutWithFee = amountsOut[i];
            }
            newBalances[i] = balances[i] - amountOutWithFee;
        }

        uint256 newInvariant = _calculateInvariant(amp, newBalances);
        uint256 invariantRatio = FixedPoint.divDown(newInvariant, currentInvariant);

        // return amountBPTIn
        return bptTotalSupply.mulUp(invariantRatio.complement());
    }

    // Computes how many tokens a user receives when burning `bptAmountIn` BPT (single-sided exit).
    function _calcTokenOutGivenBptIn(
        uint256 amplificationParameter,
        uint256[] memory balances,
        uint256 tokenIndex,
        uint256 bptAmountIn,
        uint256 bptTotalSupply,
        uint256 currentInvariant
    ) internal pure returns (uint256) {
        // Token out, so we round down overall.

        // Calculate new invariant after burning bptAmountIn:
        // newInvariant = currentInvariant * (supply - bptIn) / supply  (round up to round token amount down)
        uint256 newInvariant =
            FixedPoint.divUp(bptTotalSupply - bptAmountIn, bptTotalSupply).mulUp(currentInvariant);

        // Calculate the new balance of tokenIndex given the new invariant
        uint256 newBalanceTokenIndex = _getTokenBalanceGivenInvariantAndAllOtherBalances(
            amplificationParameter, balances, newInvariant, tokenIndex
        );

        // amountOut = oldBalance - newBalance, rounded down (-1)
        return balances[tokenIndex] - newBalanceTokenIndex - 1;
    }

    // Computes how many tokens must be sent to a pool in order to receive `bptAmountOut` BPT.
    // This is the real Balancer _calcTokenInGivenExactBptOut with internal fee handling.
    function _calcTokenInGivenExactBptOut(
        uint256 amp,
        uint256[] memory balances,
        uint256 tokenIndex,
        uint256 bptAmountOut,
        uint256 bptTotalSupply,
        uint256 currentInvariant,
        uint256 swapFeePercentage
    ) internal pure returns (uint256) {
        // Token in, so we round up overall.

        uint256 newInvariant = (bptTotalSupply + bptAmountOut).divUp(bptTotalSupply).mulUp(currentInvariant);

        // Calculate amount in without fee.
        uint256 newBalanceTokenIndex = _getTokenBalanceGivenInvariantAndAllOtherBalances(
            amp, balances, newInvariant, tokenIndex
        );
        uint256 amountInWithoutFee = newBalanceTokenIndex - balances[tokenIndex];

        // Calculate sum of all balances for weight computation
        uint256 sumBalances = 0;
        for (uint256 i = 0; i < balances.length; i++) {
            sumBalances = sumBalances + balances[i];
        }

        // Apply fee only to the taxable portion (complement of weight)
        uint256 currentWeight = balances[tokenIndex].divDown(sumBalances);
        uint256 taxablePercentage = currentWeight.complement();
        uint256 taxableAmount = amountInWithoutFee.mulUp(taxablePercentage);
        uint256 nonTaxableAmount = amountInWithoutFee - taxableAmount;

        return nonTaxableAmount + taxableAmount.divUp(FixedPoint.ONE - swapFeePercentage);
    }

    // This function calculates the balance of a given token (tokenIndex)
    // given all the other balances and the invariant
    function _getTokenBalanceGivenInvariantAndAllOtherBalances(
        uint256 amplificationParameter,
        uint256[] memory balances,
        uint256 invariant,
        uint256 tokenIndex
    ) internal pure returns (uint256) {
        // Rounds result up overall

        uint256 ampTimesTotal = amplificationParameter * balances.length;
        uint256 sum = balances[0];
        uint256 P_D = balances[0] * balances.length;
        for (uint256 j = 1; j < balances.length; j++) {
            P_D = Math.divDown(Math.mul(Math.mul(P_D, balances[j]), balances.length), invariant);
            sum = sum + balances[j];
        }
        // No need to use safe math, based on the loop above `sum` is greater than or equal to `balances[tokenIndex]`
        sum = sum - balances[tokenIndex];

        uint256 inv2 = Math.mul(invariant, invariant);
        // We remove the balance from c by multiplying it
        uint256 c =
            Math.mul(Math.mul(Math.divUp(inv2, Math.mul(ampTimesTotal, P_D)), _AMP_PRECISION), balances[tokenIndex]);
        uint256 b = sum + Math.mul(Math.divDown(invariant, ampTimesTotal), _AMP_PRECISION);

        // We iterate to find the balance
        uint256 prevTokenBalance = 0;
        // We multiply the first iteration outside the loop with the invariant to set the value of the
        // initial approximation.
        uint256 tokenBalance = Math.divUp(inv2 + c, invariant + b);

        for (uint256 i = 0; i < 30; i++) {
            prevTokenBalance = tokenBalance;

            tokenBalance =
                Math.divUp(Math.mul(tokenBalance, tokenBalance) + c, Math.mul(tokenBalance, 2) + b - invariant);

            if (tokenBalance > prevTokenBalance) {
                if (tokenBalance - prevTokenBalance <= 1) {
                    return tokenBalance;
                }
            } else if (prevTokenBalance - tokenBalance <= 1) {
                return tokenBalance;
            }
        }

        revert("STABLE_GET_BALANCE_DIDNT_CONVERGE");
    }
}

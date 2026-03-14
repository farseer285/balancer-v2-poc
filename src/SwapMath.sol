// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.30;

import {FixedPoint} from "./FixedPoint.sol";
import {StableMath} from "./StableMath.sol";


contract SwapMath {
    using FixedPoint for uint256;

    function _upscaleArray(uint256[] memory amounts, uint256[] memory scalingFactors) internal pure {
        for (uint256 i = 0; i < amounts.length; i++) {
            amounts[i] = amounts[i] * scalingFactors[i] / FixedPoint.ONE;
        }
    }

    function _downscaleUp(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return FixedPoint.divUp(amount, scalingFactor);
    }

    function _downscaleDown(uint256 amount, uint256 scalingFactor) internal pure returns (uint256) {
        return FixedPoint.divDown(amount, scalingFactor);
    }

    /// @notice Expose invariant calculation for external use (e.g., measuring D-deflation)
    function calculateInvariant(uint256 amplificationParameter, uint256[] memory balances, uint256[] memory scalingFactors)
        external
        pure
        returns (uint256)
    {
        _upscaleArray(balances, scalingFactors);
        return StableMath._calculateInvariant(amplificationParameter, balances);
    }

    /// @notice Calculate how many tokens (in raw/unscaled units) must be deposited to receive
    /// `bptAmountOut` BPT, matching ComposableStablePool's _joinSwapExactBptOutForTokenIn logic.
    /// Uses Balancer's _calcTokenInGivenExactBptOut with internal fee handling.
    function getTokenInForBptOut(
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        uint256 tokenIndex,
        uint256 bptAmountOut,
        uint256 bptTotalSupply,
        uint256 amp,
        uint256 swapFeePercentage
    ) external pure returns (uint256) {
        // Upscale balances (modifies array in-place)
        _upscaleArray(balances, scalingFactors);

        // Calculate current invariant with upscaled balances
        uint256 invariant = StableMath._calculateInvariant(amp, balances);

        // Calculate token amount in with internal fee handling (matches real Balancer)
        uint256 amountIn = StableMath._calcTokenInGivenExactBptOut(
            amp, balances, tokenIndex, bptAmountOut, bptTotalSupply, invariant, swapFeePercentage
        );

        // Downscale the result (round up)
        amountIn = _downscaleUp(amountIn, scalingFactors[tokenIndex]);

        return amountIn;
    }

    /// @notice Calculate how many tokens a user receives when burning `bptAmountIn` BPT,
    /// matching ComposableStablePool's _onExitSwap logic.
    /// Returns the raw amountOut (after swap fee deduction).
    function getTokenOutForBptIn(
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        uint256 tokenIndex,
        uint256 bptAmountIn,
        uint256 bptTotalSupply,
        uint256 amp,
        uint256 swapFeePercentage
    ) external pure returns (uint256) {
        // Upscale balances (modifies array in-place)
        _upscaleArray(balances, scalingFactors);

        // Calculate current invariant with upscaled balances
        uint256 invariant = StableMath._calculateInvariant(amp, balances);

        // Calculate token amount out (upscaled, without fee)
        uint256 amountOut = StableMath._calcTokenOutGivenBptIn(
            amp, balances, tokenIndex, bptAmountIn, bptTotalSupply, invariant
        );

        // Apply swap fee in upscaled domain first: deduct fee from output
        amountOut -= amountOut.mulUp(swapFeePercentage);

        // Then downscale the result (round down for amounts out)
        amountOut = _downscaleDown(amountOut, scalingFactors[tokenIndex]);

        return amountOut;
    }

    /// @notice Calculate how much BPT must be burned to receive `tokenAmountOut` of a single token
    /// (GIVEN_OUT exit swap). Matches ComposableStablePool's _exitSwapExactTokenOutForBptIn logic.
    /// Uses Balancer's _calcBptInGivenExactTokensOut with internal fee handling.
    function getBptInForTokenOut(
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        uint256 tokenIndex,
        uint256 tokenAmountOut,
        uint256 bptTotalSupply,
        uint256 amp,
        uint256 swapFeePercentage
    ) external pure returns (uint256) {
        // Upscale the token amount out and balances
        uint256 upscaledAmountOut = tokenAmountOut * scalingFactors[tokenIndex] / FixedPoint.ONE;
        _upscaleArray(balances, scalingFactors);

        // Build amountsOut array with single non-zero entry (matches real Balancer pattern)
        uint256[] memory amountsOut = new uint256[](balances.length);
        amountsOut[tokenIndex] = upscaledAmountOut;

        // Calculate current invariant
        uint256 invariant = StableMath._calculateInvariant(amp, balances);

        // Calculate BPT needed with internal fee handling (matches real Balancer)
        uint256 bptIn = StableMath._calcBptInGivenExactTokensOut(
            amp, balances, amountsOut, bptTotalSupply, invariant, swapFeePercentage
        );

        return bptIn;
    }

    function getAfterSwapOutBalances(
        uint256[] memory balances,
        uint256[] memory scalingFactors,
        uint256 indexIn,
        uint256 indexOut,
        uint256 swapOutAmount,
        uint256 amp,
        uint256 swapFeePercentage
    ) external pure returns (uint256[] memory) {
        uint256 balancesIn = balances[indexIn];
        uint256 balancesOut = balances[indexOut];

        _upscaleArray(balances, scalingFactors);

        uint256 swapOutAmountAfterScale = swapOutAmount * scalingFactors[indexOut] / FixedPoint.ONE;

        uint256 invariant = StableMath._calculateInvariant(amp, balances);
        uint256 amountIn =
            StableMath._calcInGivenOut(amp, balances, indexIn, indexOut, swapOutAmountAfterScale, invariant);

        // Apply swap fee in upscaled domain first: amountIn / (1 - swapFee)
        amountIn = amountIn.divUp(swapFeePercentage.complement());

        // Then downscale to raw units (round up)
        uint256 rawAmountInWithFee = _downscaleUp(amountIn, scalingFactors[indexIn]);

        uint256[] memory newBalances = new uint256[](balances.length);
        newBalances[indexIn] = balancesIn + rawAmountInWithFee;
        newBalances[indexOut] = balancesOut - swapOutAmount;

        return newBalances;
    }
}

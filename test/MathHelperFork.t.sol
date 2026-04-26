// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";
import {MathHelper} from "src/MathHelper.sol";

/// @notice Fork test: compare the locally re-implemented `MathHelper` against
///         the real on-chain helper at 0x679B362B...381e at the attack block.
///         Reproduces the call from tx 0x6ed0...9742 (selector 0x524c9e20).
contract MathHelperFork is Test {
    address constant ON_CHAIN  = 0x679B362B9f38BE63FbD4A499413141A997eb381e;
    address constant ADMIN0    = 0x506D1f9EFe24f0d47853aDca907EB8d89AE03207;
    address constant ADMIN1    = 0x766A892f8BA102556C8537d02fcA0ff4CaCfC492;
    uint256 constant FORK_BLK  = 23717397;

    bytes constant CALLDATA_FROM_TX = hex"524c9e20"
        // head (7 slots)
        hex"00000000000000000000000000000000000000000000000000000000000000e0"  // balances offset
        hex"0000000000000000000000000000000000000000000000000000000000000140"  // scalingFactors offset
        hex"0000000000000000000000000000000000000000000000000000000000000000"  // tokenIndexIn  = 0
        hex"0000000000000000000000000000000000000000000000000000000000000001"  // tokenIndexOut = 1
        hex"00000000000000000000000000000000000000000000000000000000000105a6"  // tokenAmountOut = 66982
        hex"0000000000000000000000000000000000000000000000000000000000030d40"  // amp = 200000
        hex"00000000000000000000000000000000000000000000000000005af3107a4000"  // swapFee = 1e14
        // balances[]
        hex"0000000000000000000000000000000000000000000000000000000000000002"
        hex"00000000000000000000000000000000000000000000000000000000000105b8"
        hex"00000000000000000000000000000000000000000000000000000000000105b8"
        // scalingFactors[]
        hex"0000000000000000000000000000000000000000000000000000000000000002"
        hex"0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        hex"0000000000000000000000000000000000000000000000000eaf3dd1c94b51f3";

    MathHelper internal local;

    function setUp() public {
        vm.createSelectFork("ETH", FORK_BLK);
        local = new MathHelper(ADMIN0, ADMIN1);
    }

    /// @dev Helper: invoke the on-chain helper with the EXACT calldata,
    /// driving tx.origin to ADMIN0 so the contract's auth check passes.
    /// `staticcall` is not used because Forge doesn't apply vm.prank to the
    /// tx.origin of a low-level staticcall in the same way; a regular call
    /// keeps it simple and the function is read-only anyway.
    function _onChainCall() internal returns (uint256[] memory) {
        vm.prank(ADMIN0, ADMIN0);
        (bool ok, bytes memory ret) = ON_CHAIN.call(CALLDATA_FROM_TX);
        require(ok, "on-chain call failed");
        return abi.decode(ret, (uint256[]));
    }

    function _localCall() internal returns (uint256[] memory) {
        vm.prank(ADMIN0, ADMIN0);
        (bool ok, bytes memory ret) = address(local).call(CALLDATA_FROM_TX);
        require(ok, "local call failed");
        return abi.decode(ret, (uint256[]));
    }

    /// @notice Sanity-check: replay the EXACT calldata against the on-chain
    /// contract and assert the documented return [374353, 18].
    function test_onChainGroundTruth() public {
        uint256[] memory out = _onChainCall();
        console.log("on-chain out[0]:", out[0]);
        console.log("on-chain out[1]:", out[1]);
        assertEq(out.length, 2,      "length");
        assertEq(out[0],     374353, "out[0]");
        assertEq(out[1],     18,     "out[1]");
    }

    /// @notice Replay the exact calldata against the local re-implementation
    /// using the same caller (so the tx.origin gate passes), and assert
    /// element-wise equality with the on-chain return.
    function test_localMatchesOnChain_replayCalldata() public {
        uint256[] memory onOut  = _onChainCall();
        uint256[] memory locOut = _localCall();

        console.log("on-chain[0]:", onOut[0], " local[0]:", locOut[0]);
        console.log("on-chain[1]:", onOut[1], " local[1]:", locOut[1]);
        assertEq(locOut.length, onOut.length, "length mismatch");
        for (uint256 i = 0; i < onOut.length; i++) {
            assertEq(locOut[i], onOut[i], "element mismatch");
        }
    }

    /// @notice Same test but invoking the typed Solidity API (catches signature
    /// regressions independent of raw calldata replay).
    function test_localMatchesOnChain_typedAPI() public {
        uint256[] memory bal = new uint256[](2);
        bal[0] = 67000;
        bal[1] = 67000;
        uint256[] memory sf = new uint256[](2);
        sf[0] = 1e18;
        sf[1] = 1058132408689971699;

        uint256[] memory onOut = _onChainCall();

        vm.prank(ADMIN0, ADMIN0);
        uint256[] memory locOut =
            local.swapGivenOut(bal, sf, 0, 1, 66982, 200000, 1e14);

        assertEq(locOut.length, onOut.length, "length mismatch");
        for (uint256 i = 0; i < onOut.length; i++) {
            assertEq(locOut[i], onOut[i], "element mismatch");
        }
    }
}

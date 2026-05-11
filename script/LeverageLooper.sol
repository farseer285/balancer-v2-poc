// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/*
 * Reconstructed from runtime bytecode of contract:
 *   0x554A063e5A7Eb42ae0555eb265C190C66d1a4CC8  (Ethereum mainnet)
 *
 * Deployment context
 * ------------------
 * Created at block 23717398 by EOA 0x5aF00b073abB9F88832353Bd4C919caAa114c972
 * (BitFinding interception agent), in the same block as the BitFinding back-run
 * transactions reacting to the Balancer V2 Composable Stable Pool incident.
 * Despite that co-location, the bytecode reviewed below references no Balancer
 * contract, BPT, or Balancer-specific selector (flashLoan / batchSwap /
 * joinPool / exitPool / manageUserBalance / queryBatchSwap, etc.). The only
 * external protocols reached are Aave V3 (POOL) and a Uniswap-V3-router-shaped
 * call against the agent EOA. The contract is therefore not part of the
 * Balancer rescue path; co-deployment is a deployer-side artefact only.
 *
 * The names of functions / state variables are inferred ("not the original
 * Solidity source"): the on-chain selectors are written as comments next to
 * each public symbol so they can be matched back to the deployed contract.
 *
 * Behaviour summary
 * -----------------
 * The contract implements a one-shot Aave-V3 + Uniswap-V3 "leverage loop"
 * for a per-user WETH/USDC long-WETH position:
 *
 *   open():
 *     - pull `amount` WETH from msg.sender
 *     - up to `loops` (max 15) iterations of:
 *           POOL.supply(WETH, current, msg.sender, 0)
 *           borrow = current * 7200 * 4000 / 10000   // hard-coded
 *           POOL.borrow(USDC, borrow, 2, 0, msg.sender)
 *           current = SwapRouter.exactInputSingle(USDC -> WETH, fee 500)
 *           if (current < 1e14) break
 *     - persist Position{collateral, debt, lastWeth, openBlock, opened=true}
 *
 *   unwind():
 *     - pull `debt` USDC from msg.sender
 *     - USDC.approve(POOL, debt)                  // re-approved per call
 *     - POOL.repay(USDC, debt, 2, msg.sender)
 *     - POOL.withdraw(WETH, type(uint256).max, msg.sender)
 *     - delete the position
 *
 * Selector ⇄ name caveats (verified against runtime bytecode):
 *   0xd2d23a37  open(...)            – 4byte.directory has no entry; the
 *                                      decoder accepts (uint256, uint256) so
 *                                      the call signature is verified, the
 *                                      symbol name is a guess.
 *   0xe17eb26f  BPS_LTV()            – 4byte.directory has no entry; the
 *                                      getter immediately returns 7200, the
 *                                      symbol name is a guess.
 *   0xfe6bcd7c  userAccountData(address)
 *                                    – the contract exposes this as an
 *                                      external view; the dispatcher entry
 *                                      for selector 0xfe6bcd7c appears once
 *                                      and the handler issues a single
 *                                      STATICCALL to POOL with selector
 *                                      0xbf92857c (Aave V3
 *                                      getUserAccountData(address)) and
 *                                      returns its full 6-uint256 tuple
 *                                      verbatim. 4byte.directory happens to
 *                                      list 0xfe6bcd7c under the unrelated
 *                                      registered name "getHealthFactor
 *                                      (address)"; that mapping is a hash
 *                                      collision-by-registration, not a
 *                                      semantic match: the body neither
 *                                      computes nor returns a single
 *                                      health-factor uint256, and there is
 *                                      no outbound call to any
 *                                      getHealthFactor anywhere in the
 *                                      bytecode. The symbol name actually
 *                                      chosen by the author is not
 *                                      recoverable from runtime bytecode;
 *                                      `userAccountData` is used here only
 *                                      because it matches the function's
 *                                      observable behaviour and return shape.
 */

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IAavePool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf) external returns (uint256);
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24  fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata p) external returns (uint256);
}

contract LeverageLooper {
    // --- storage ----------------------------------------------------------
    address public owner;                                   // slot 0   (selector 0x8da5cb5b)
    mapping(address => Position) public positions;          // slot 1   (selector 0x55f57510)

    struct Position {
        uint256 collateral;     // sum of WETH supplied to Aave across all loops
        uint256 debt;           // sum of USDC borrowed from Aave across all loops
        uint256 lastWeth;       // WETH amount left in the contract after the final swap
        uint256 openBlock;      // block.number when the position was opened
        bool    opened;
    }

    // --- constants (immediately-returned values from public getters) ------
    address public constant POOL    = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2; // selector 0x7535d246
    address public constant USDC    = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // selector 0x89a30271
    address public constant WETH    = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // selector 0xad5c4648
    // Hard-coded operator EOA (BitFinding: Whitehat Bot). Granted unbounded USDC
    // approval so it can pull funds out of this contract at any time. NOT a DEX router.
    address public constant UNISWAP = 0x5af00b073aBb9F88832353Bd4C919caAa114c972; // selector 0xc745d9e7
    uint256 public constant BPS_LTV = 7200;                                       // selector 0xe17eb26f

    uint256 private constant PRICE     = 4000;
    uint256 private constant BPS       = 10000;
    uint256 private constant DUST_WETH = 1e14;
    uint256 private constant MAX_LOOPS = 15;

    // --- events (topics observed in LOG2 instructions) --------------------
    // 0x83750c920db23bf6f5e4cca4e4c2b597b1f1e938f51293374711fca943a1a29d
    event Opened(address indexed user, uint256 collateral, uint256 debt, uint256 lastWeth, uint256 openBlock, bool opened);
    // 0x0a9e152811b4bdfb8dfb583a486e63c1072a8179246c0bcaea9b58c2cc1370d7
    event Closed(address indexed user, uint256 collateral, uint256 debt);

    // --- public API -------------------------------------------------------
    /// selector 0xd2d23a37
    function open(uint256 amount, uint256 loops) external {
        Position storage p = positions[msg.sender];
        require(!p.opened, "Position exists");
        require(loops < MAX_LOOPS); // bytecode reverts with a 14-byte error string here

        IERC20(WETH).transferFrom(msg.sender, address(this), amount);
        IERC20(WETH).approve(POOL,    type(uint256).max);
        IERC20(USDC).approve(POOL,    type(uint256).max);
        IERC20(USDC).approve(UNISWAP, type(uint256).max);

        uint256 totalCollateral;
        uint256 totalDebt;
        uint256 current = amount;
        for (uint256 i = 0; i < loops; ++i) {
            IAavePool(POOL).supply(WETH, current, msg.sender, 0);
            totalCollateral += current;

            uint256 toBorrow = (current * BPS_LTV * PRICE) / BPS;
            IAavePool(POOL).borrow(USDC, toBorrow, 2, 0, msg.sender);
            totalDebt += toBorrow;

            current = _swapUsdcForWeth(toBorrow);
            if (current < DUST_WETH) break;
        }

        p.collateral = totalCollateral;
        p.debt       = totalDebt;
        p.lastWeth   = current;
        p.openBlock  = block.number;
        p.opened     = true;
        emit Opened(msg.sender, totalCollateral, totalDebt, current, block.number, true);
    }

    /// selector 0x00cf1d72
    function unwind() external {
        Position memory p = positions[msg.sender];
        require(p.opened, "No position");

        IERC20(USDC).transferFrom(msg.sender, address(this), p.debt);
        IERC20(USDC).approve(POOL, p.debt);
        IAavePool(POOL).repay(USDC, p.debt, 2, msg.sender);
        IAavePool(POOL).withdraw(WETH, type(uint256).max, msg.sender);

        delete positions[msg.sender];
        emit Closed(msg.sender, p.collateral, p.debt);
    }

    /// selector 0xfe6bcd7c — thin proxy for Aave's getUserAccountData(address)
    /// (selector 0xbf92857c on POOL).  The on-chain function name is not
    /// recoverable from the bytecode; it returns the 6 uint256 fields that
    /// Aave's view returns, in the same order.
    function userAccountData(address asset) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    ) {
        (bool ok, bytes memory ret) = POOL.staticcall(abi.encodeWithSelector(0xbf92857c, asset));
        require(ok);
        (
            totalCollateralBase,
            totalDebtBase,
            availableBorrowsBase,
            currentLiquidationThreshold,
            ltv,
            healthFactor
        ) = abi.decode(ret, (uint256, uint256, uint256, uint256, uint256, uint256));
    }

    // --- internal ---------------------------------------------------------
    function _swapUsdcForWeth(uint256 usdcIn) internal returns (uint256) {
        return ISwapRouter(UNISWAP).exactInputSingle(
            ISwapRouter.ExactInputSingleParams({
                tokenIn:           USDC,
                tokenOut:          WETH,
                fee:               500,
                recipient:         address(this),
                deadline:          block.timestamp,
                amountIn:          usdcIn,
                amountOutMinimum:  0,
                sqrtPriceLimitX96: 0
            })
        );
    }
}

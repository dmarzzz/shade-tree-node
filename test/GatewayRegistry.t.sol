// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "./Cheats.sol";
import {GatewayRegistry} from "../contracts/GatewayRegistry.sol";

contract GatewayRegistryTest is Cheats {
    // Demo params, matching the local anvil demo.
    uint256 constant BOND = 0.01 ether;
    uint256 constant UNBONDING = 300;
    uint256 constant MIN_UNBONDING = 270;

    GatewayRegistry reg;

    address constant OWNER = address(0x0140); // governance / slasher
    address constant OP_A = address(0xA11CE); // operator A
    address constant OP_B = address(0xB0B);   // operator B
    address constant RECIPIENT = address(0xBEEF);
    address constant RECEIVER = address(0xCAFE); // slash receiver (e.g. treasury)

    function setUp() public {
        reg = new GatewayRegistry(BOND, UNBONDING, MIN_UNBONDING, OWNER);
        vm.deal(OP_A, 1 ether);
        vm.deal(OP_B, 1 ether);
    }

    // ---- constructor guards ---------------------------------------------------

    function test_constructor_rejects_zero_bond() public {
        vm.expectRevert(GatewayRegistry.BadBond.selector);
        new GatewayRegistry(0, UNBONDING, MIN_UNBONDING, OWNER);
    }

    function test_constructor_rejects_short_unbonding() public {
        vm.expectRevert(GatewayRegistry.UnbondingTooShort.selector);
        new GatewayRegistry(BOND, MIN_UNBONDING - 1, MIN_UNBONDING, OWNER);
    }

    function test_owner_defaults_to_deployer_when_zero() public {
        GatewayRegistry r = new GatewayRegistry(BOND, UNBONDING, MIN_UNBONDING, address(0));
        assertEq(r.owner(), address(this));
    }

    // ---- register -------------------------------------------------------------

    function test_register_admits_and_is_staked() public {
        assertFalse(reg.isStaked(OP_A));
        vm.prank(OP_A);
        reg.register{value: BOND}();
        assertTrue(reg.isStaked(OP_A), "operator should be staked");
        assertEq(reg.activeCount(), 1);
    }

    function test_register_rejects_wrong_bond() public {
        vm.prank(OP_A);
        vm.expectRevert(GatewayRegistry.BadBond.selector);
        reg.register{value: BOND - 1}();
    }

    function test_register_rejects_double_stake() public {
        vm.startPrank(OP_A);
        reg.register{value: BOND}();
        vm.expectRevert(GatewayRegistry.AlreadyStaked.selector);
        reg.register{value: BOND}();
        vm.stopPrank();
    }

    // ---- exit + withdraw ------------------------------------------------------

    function test_exit_then_withdraw_after_unbonding() public {
        vm.startPrank(OP_A);
        reg.register{value: BOND}();
        reg.initiateExit();
        assertFalse(reg.isStaked(OP_A), "exiting operator leaves the active set");
        assertEq(reg.activeCount(), 0);
        assertEq(reg.withdrawableAt(OP_A), block.timestamp + UNBONDING);

        // still bonded before the window elapses
        vm.expectRevert(GatewayRegistry.StillBonded.selector);
        reg.withdraw(RECIPIENT);

        vm.warp(block.timestamp + UNBONDING);
        reg.withdraw(RECIPIENT);
        vm.stopPrank();
        assertEq(RECIPIENT.balance, BOND, "bond returned to recipient");
    }

    function test_withdraw_requires_exit_first() public {
        vm.startPrank(OP_A);
        reg.register{value: BOND}();
        vm.expectRevert(GatewayRegistry.NotExiting.selector);
        reg.withdraw(RECIPIENT);
        vm.stopPrank();
    }

    function test_only_operator_can_exit() public {
        vm.prank(OP_A);
        reg.register{value: BOND}();
        vm.prank(OP_B);
        vm.expectRevert(GatewayRegistry.NotStaked.selector); // OP_B has no stake of its own
        reg.initiateExit();
    }

    // ---- slash (governance) ---------------------------------------------------

    function test_owner_can_slash_active() public {
        vm.prank(OP_A);
        reg.register{value: BOND}();

        vm.prank(OWNER);
        reg.slash(OP_A, RECEIVER);
        assertFalse(reg.isStaked(OP_A), "slashed operator is gone");
        assertEq(reg.activeCount(), 0);
        assertEq(RECEIVER.balance, BOND, "bond paid to receiver");
    }

    function test_owner_can_slash_while_exiting() public {
        // the "exit to dodge slash" escape must stay closed during unbonding.
        vm.startPrank(OP_A);
        reg.register{value: BOND}();
        reg.initiateExit();
        vm.stopPrank();

        vm.warp(block.timestamp + UNBONDING - 1); // still inside the window
        vm.prank(OWNER);
        reg.slash(OP_A, RECEIVER);
        assertEq(RECEIVER.balance, BOND, "mid-unbonding operator still slashable");
    }

    function test_non_owner_cannot_slash() public {
        vm.prank(OP_A);
        reg.register{value: BOND}();
        vm.prank(OP_B);
        vm.expectRevert(GatewayRegistry.NotOwner.selector);
        reg.slash(OP_A, RECEIVER);
    }

    function test_slash_requires_stake() public {
        vm.prank(OWNER);
        vm.expectRevert(GatewayRegistry.NotStaked.selector);
        reg.slash(OP_A, RECEIVER);
    }

    // ---- ownership ------------------------------------------------------------

    function test_transfer_ownership() public {
        vm.prank(OWNER);
        reg.transferOwnership(OP_B);
        assertEq(reg.owner(), OP_B);
        // old owner can no longer slash
        vm.prank(OP_A);
        reg.register{value: BOND}();
        vm.prank(OWNER);
        vm.expectRevert(GatewayRegistry.NotOwner.selector);
        reg.slash(OP_A, RECEIVER);
    }
}

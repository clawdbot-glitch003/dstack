/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

/// @notice Halmos symbolic tests for DstackApp.
/// Run with `halmos --contract DstackAppSymbolicTest`.
/// Each `check_*` function has its arguments treated as symbolic; bodies
/// state the property as a Solidity-level assertion.
contract DstackAppSymbolicTest is Test {
    DstackApp internal app;
    address internal constant OWNER = address(0xA11CE);
    address internal constant NON_OWNER = address(0xB0B);

    function setUp() public {
        // Deploy proxy directly via ERC1967, bypassing the OZ Upgrades plugin
        // (which uses FFI and is unsuitable for symbolic execution).
        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)", OWNER, false, false, bytes32(0), bytes32(0)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        app = DstackApp(address(proxy));
    }

    // ---------------------------------------------------------------
    // Owner-gated mutations: every state-changing method reverts when
    // called by anyone other than the owner.
    // ---------------------------------------------------------------

    function check_AddComposeHash_OnlyOwner(address caller, bytes32 hash) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.addComposeHash.selector, hash));
        assert(!ok);
    }

    function check_RemoveComposeHash_OnlyOwner(address caller, bytes32 hash) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.removeComposeHash.selector, hash));
        assert(!ok);
    }

    function check_AddDevice_OnlyOwner(address caller, bytes32 deviceId) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.addDevice.selector, deviceId));
        assert(!ok);
    }

    function check_RemoveDevice_OnlyOwner(address caller, bytes32 deviceId) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.removeDevice.selector, deviceId));
        assert(!ok);
    }

    function check_SetAllowAnyDevice_OnlyOwner(address caller, bool flag) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.setAllowAnyDevice.selector, flag));
        assert(!ok);
    }

    function check_SetRequireTcbUpToDate_OnlyOwner(address caller, bool flag) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.setRequireTcbUpToDate.selector, flag));
        assert(!ok);
    }

    function check_DisableUpgrades_OnlyOwner(address caller) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.disableUpgrades.selector));
        assert(!ok);
    }

    // ---------------------------------------------------------------
    // disableUpgrades monotonicity: after disableUpgrades() succeeds,
    // every subsequent upgrade attempt — by any caller, to any impl —
    // must revert.
    // ---------------------------------------------------------------

    function check_DisableUpgradesMonotonic(address upgrader, address newImpl, bytes calldata data) external {
        vm.prank(OWNER);
        app.disableUpgrades();

        vm.prank(upgrader);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.upgradeToAndCall.selector, newImpl, data));
        assert(!ok);
    }

    // ---------------------------------------------------------------
    // isAppAllowed decision table. For any symbolic bootInfo and any
    // setting of the three relevant flags + whitelists, the returned
    // boolean matches the policy formula exactly.
    //
    // We deliberately set `tcbStatus = "UpToDate"` (concrete) here.
    // The string-compare branch is exercised separately in the unit
    // tests; making it fully symbolic interacts poorly with Halmos's
    // bounded-byte modeling and inflates the search space without
    // adding signal.
    // ---------------------------------------------------------------

    function check_IsAppAllowed_DecisionTable_TcbUpToDate(
        bytes32 composeHash,
        bytes32 deviceId,
        bool addCompose,
        bool addDevice,
        bool anyDevice
    )
        external
    {
        vm.startPrank(OWNER);
        if (addCompose) app.addComposeHash(composeHash);
        if (addDevice) app.addDevice(deviceId);
        app.setAllowAnyDevice(anyDevice);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed,) = app.isAppAllowed(bootInfo);
        bool expected = addCompose && (anyDevice || addDevice);
        assert(allowed == expected);
    }

    // ---------------------------------------------------------------
    // TCB byte-exact policy. When `requireTcbUpToDate` is on, the only
    // accepted `tcbStatus` is the byte-exact ASCII string "UpToDate"
    // (8 bytes). Any other string — case variations, trailing nulls,
    // longer prefixes — is rejected. This is the contract dstack's
    // off-chain attestation pipeline must honor.
    // ---------------------------------------------------------------

    function check_TcbStatus_OnlyExactUpToDateAccepted(string memory tcbStatus) external {
        bytes32 composeHash = bytes32(uint256(1));

        vm.startPrank(OWNER);
        app.addComposeHash(composeHash);
        app.setAllowAnyDevice(true);
        app.setRequireTcbUpToDate(true);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: tcbStatus,
            advisoryIds: new string[](0)
        });

        (bool allowed,) = app.isAppAllowed(bootInfo);
        bool exactMatch = keccak256(bytes(tcbStatus)) == keccak256(bytes("UpToDate"));
        assert(allowed == exactMatch);
    }

    // Concrete cases nail down the byte-exactness in case Halmos's
    // symbolic-string modeling has surprises.
    function check_TcbStatus_RejectsLowercase() external {
        bytes32 composeHash = bytes32(uint256(1));
        vm.startPrank(OWNER);
        app.addComposeHash(composeHash);
        app.setAllowAnyDevice(true);
        app.setRequireTcbUpToDate(true);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "uptodate",
            advisoryIds: new string[](0)
        });
        (bool allowed,) = app.isAppAllowed(bootInfo);
        assert(!allowed);
    }

    function check_TcbStatus_RejectsTrailingChars() external {
        bytes32 composeHash = bytes32(uint256(1));
        vm.startPrank(OWNER);
        app.addComposeHash(composeHash);
        app.setAllowAnyDevice(true);
        app.setRequireTcbUpToDate(true);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "UpToDate ",
            advisoryIds: new string[](0)
        });
        (bool allowed,) = app.isAppAllowed(bootInfo);
        assert(!allowed);
    }

    // ---------------------------------------------------------------
    // 5-arg legacy initializer leaves the new TCB slot at zero,
    // regardless of any of the other init inputs.
    // ---------------------------------------------------------------

    function check_Initialize5Arg_DefaultsTcbToFalse(
        address initialOwner,
        bool disableUpgrades,
        bool allowAnyDevice,
        bytes32 deviceId,
        bytes32 composeHash
    )
        external
    {
        vm.assume(initialOwner != address(0));

        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)",
            initialOwner,
            disableUpgrades,
            allowAnyDevice,
            deviceId,
            composeHash
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        DstackApp fresh = DstackApp(address(proxy));

        assert(!fresh.requireTcbUpToDate());
    }

    // ---------------------------------------------------------------
    // 6-arg initializer honors the TCB flag exactly.
    // ---------------------------------------------------------------

    function check_Initialize6Arg_HonorsTcbFlag(
        address initialOwner,
        bool flag,
        bool allowAnyDevice,
        bytes32 deviceId,
        bytes32 composeHash
    )
        external
    {
        vm.assume(initialOwner != address(0));

        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bool,bytes32,bytes32)",
            initialOwner,
            false,
            flag,
            allowAnyDevice,
            deviceId,
            composeHash
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        DstackApp fresh = DstackApp(address(proxy));

        assert(fresh.requireTcbUpToDate() == flag);
    }
}

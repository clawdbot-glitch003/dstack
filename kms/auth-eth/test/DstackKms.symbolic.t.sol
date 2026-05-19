/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

/// @notice Halmos symbolic tests for DstackKms.
/// Run with `halmos --contract DstackKmsSymbolicTest`.
contract DstackKmsSymbolicTest is Test {
    DstackKms internal kms;
    DstackApp internal appImpl;
    address internal constant OWNER = address(0xA11CE);

    function setUp() public {
        appImpl = new DstackApp();

        DstackKms kmsImpl = new DstackKms();
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (OWNER, address(appImpl)));
        ERC1967Proxy proxy = new ERC1967Proxy(address(kmsImpl), initData);
        kms = DstackKms(address(proxy));
    }

    // ---------------------------------------------------------------
    // Owner-gated mutations across the KMS write surface.
    // ---------------------------------------------------------------

    function check_SetGatewayAppId_OnlyOwner(address caller, string calldata id) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.setGatewayAppId.selector, id));
        assert(!ok);
    }

    function check_AddKmsAggregatedMr_OnlyOwner(address caller, bytes32 mr) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.addKmsAggregatedMr.selector, mr));
        assert(!ok);
    }

    function check_RemoveKmsAggregatedMr_OnlyOwner(address caller, bytes32 mr) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.removeKmsAggregatedMr.selector, mr));
        assert(!ok);
    }

    function check_AddKmsDevice_OnlyOwner(address caller, bytes32 deviceId) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.addKmsDevice.selector, deviceId));
        assert(!ok);
    }

    function check_RemoveKmsDevice_OnlyOwner(address caller, bytes32 deviceId) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.removeKmsDevice.selector, deviceId));
        assert(!ok);
    }

    function check_AddOsImageHash_OnlyOwner(address caller, bytes32 imageHash) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.addOsImageHash.selector, imageHash));
        assert(!ok);
    }

    function check_RemoveOsImageHash_OnlyOwner(address caller, bytes32 imageHash) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.removeOsImageHash.selector, imageHash));
        assert(!ok);
    }

    function check_SetAppImplementation_OnlyOwner(address caller, address impl) external {
        vm.assume(caller != OWNER);
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.setAppImplementation.selector, impl));
        assert(!ok);
    }

    // NOTE: `registerApp` is intentionally `public` with no access control —
    // it is the factory hook called by `deployAndRegisterApp` and is also
    // open to direct external use. It is NOT an owner-only function. Halmos
    // confirmed this: any non-zero address can be registered by anyone.
    // Authorization is still gated downstream by the owner-controlled
    // `allowedOsImages` whitelist and the registered app's own
    // `isAppAllowed` logic.
    function check_RegisterApp_AnyCallerCanRegisterNonZeroAddress(address caller, address appId) external {
        vm.assume(appId != address(0));
        vm.prank(caller);
        kms.registerApp(appId);
        assert(kms.registeredApps(appId));
    }

    function check_RegisterApp_RejectsZeroAddress(address caller) external {
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.registerApp.selector, address(0)));
        assert(!ok);
    }

    // ---------------------------------------------------------------
    // isAppAllowed short-circuits: unregistered app and unknown OS
    // image must each force a reject regardless of any other input.
    // ---------------------------------------------------------------

    function check_IsAppAllowed_RejectsUnregisteredApp(IAppAuth.AppBootInfo calldata bootInfo) external view {
        // No apps registered in setUp(), so any bootInfo.appId is rejected.
        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256(bytes("App not registered")));
    }

    function check_IsAppAllowed_RejectsUnknownOsImage(address appId, IAppAuth.AppBootInfo calldata bootInfo) external {
        vm.assume(appId != address(0));

        // Register the appId so the registration check passes.
        vm.prank(OWNER);
        kms.registerApp(appId);

        // No OS image is in the allowlist, so any bootInfo.osImageHash rejects.
        vm.assume(bootInfo.appId == appId);
        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256(bytes("OS image is not allowed")));
    }

    // ---------------------------------------------------------------
    // deployAndRegisterApp atomicity + TCB propagation: when the
    // factory call succeeds, the returned address is registered AND
    // the proxy's `requireTcbUpToDate` reflects the supplied flag.
    // ---------------------------------------------------------------

    function check_DeployAndRegisterApp_Atomic(
        address initialOwner,
        bool disableUpgrades,
        bool requireTcbUpToDate,
        bool allowAnyDevice
    )
        external
    {
        vm.assume(initialOwner != address(0));

        vm.prank(OWNER);
        address appId = kms.deployAndRegisterApp(
            initialOwner, disableUpgrades, requireTcbUpToDate, allowAnyDevice, bytes32(0), bytes32(0)
        );

        assert(kms.registeredApps(appId));
        assert(DstackApp(appId).requireTcbUpToDate() == requireTcbUpToDate);
        assert(DstackApp(appId).allowAnyDevice() == allowAnyDevice);
        assert(DstackApp(appId).owner() == initialOwner);
    }

    // Legacy 5-arg overload always defaults `requireTcbUpToDate` to false.
    function check_DeployAndRegisterApp5Arg_DefaultsTcbToFalse(
        address initialOwner,
        bool disableUpgrades,
        bool allowAnyDevice
    )
        external
    {
        vm.assume(initialOwner != address(0));

        vm.prank(OWNER);
        address appId = kms.deployAndRegisterApp(initialOwner, disableUpgrades, allowAnyDevice, bytes32(0), bytes32(0));

        assert(kms.registeredApps(appId));
        assert(!DstackApp(appId).requireTcbUpToDate());
    }
}

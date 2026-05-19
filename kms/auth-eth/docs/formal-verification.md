<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# Formal Verification Plan — `kms/auth-eth`

A layered approach: cheap static analysis → SMTChecker invariants → Halmos
symbolic tests → (optional) Certora. Each layer is independently mergeable.

The **formal specification** these layers verify against lives in
[`specification.md`](./specification.md). The spec is normative — code
and tests track the spec, not the other way around.

Reference: <https://github.com/leonardoalt/ethereum_formal_verification_overview>

## Targets

The two contracts under verification are authorization gates for TEE workloads;
correctness matters more than gas.

- `contracts/DstackApp.sol` (209 LOC) — per-app boot authorization
- `contracts/DstackKms.sol` (276 LOC) — KMS whitelist + factory
- `contracts/IAppAuth.sol`, `contracts/IAppAuthBasicManagement.sol` — interfaces

## Layer 0 — Slither (static analysis)

Not formal verification but the standard first pass. Catches reentrancy,
shadowing, uninitialized state, unsafe `delegatecall`, etc.

- [ ] Install slither-analyzer (Python via pipx or as a uv tool)
- [ ] Add `slither.config.json` at `kms/auth-eth/` excluding `lib/`, `out/`,
      `cache/`, `node_modules/`, `test/` (focus on production contracts)
- [ ] Run baseline `slither contracts/` and triage findings into:
      - real → fix
      - false-positive / wontfix → suppress with `// slither-disable-next-line`
        and a justifying comment
<!-- CI integration intentionally not added — see "What's intentionally not
in scope" below. Slither runs locally before risky changes. -->
- [x] Slither runs locally; no CI gate (intentional)
- [ ] Update `kms/auth-eth/README.md` with one line on how to run Slither locally

**Effort:** ~1h. **Owner:** _tbd_.

## Layer 1 — SMTChecker (deferred)

**Status: deferred.** Originally planned as the cheap free tier, but the
practical setup cost is high enough that it's not worth doing before Halmos.

What was tried (and why it fails to deliver value here):

1. **CHC engine + `solvers = ["z3"]`:** solc's binary distributions on
   foundry's `svm` (Solidity version manager) are not compiled with z3
   linkage. Result: every analysis emits `Warning (7649): CHC analysis was
   not possible since no Horn solver was found and enabled`.
2. **CHC engine + `solvers = ["smtlib2"]`:** solc emits SMT-LIB2 queries
   but does not auto-spawn an external solver. Without a wrapper, nothing
   actually runs.
3. **BMC engine:** runs, but on our OZ-upgradeable contracts emits only
   `Warning (5724): SMTChecker: N unsupported language feature(s)` —
   delegatecall, complex modifiers, and proxy patterns aren't in scope.
   Net useful findings: zero.

To enable SMTChecker properly we'd need to either:
- build solc from source with `USE_Z3=1`, ship the binary, point forge at it
  (via `solc = "/path/to/our/solc"` in `foundry.toml`);
- or run solc in a container image like `ethereum/solc:0.8.24-z3` and wire
  it into CI.

Either path is significant infra work. Halmos (Layer 2) covers everything
SMTChecker would prove on our contracts (asserts, overflows, owner-gated
mutations) while also handling the symbolic-input cases SMTChecker can't
(TCB string compare, `isAppAllowed` decision table), using a solver that's
already a Foundry-native install.

Revisit Layer 1 only if we want defense-in-depth alongside Halmos.

## Layer 2 — Halmos symbolic tests

[Halmos](https://github.com/a16z/halmos) runs Foundry-style tests with all
function arguments as symbolic variables. Sweet spot for our contracts: we
reuse the existing `.t.sol` scaffolding and OZ-foundry-upgrades plugin.

### Setup

- [x] `pipx install halmos` documented in `README.md`
- [ ] No CI integration (intentional — see "What's intentionally not in
      scope" below)

### `DstackApp` symbolic properties (`test/DstackApp.symbolic.t.sol`)

- [ ] `check_AddComposeHash_OnlyOwner(address caller, bytes32 hash)` — call
      reverts iff `caller != owner`
- [ ] `check_RemoveComposeHash_OnlyOwner` (same shape)
- [ ] `check_AddDevice_OnlyOwner`
- [ ] `check_RemoveDevice_OnlyOwner`
- [ ] `check_SetAllowAnyDevice_OnlyOwner`
- [ ] `check_SetRequireTcbUpToDate_OnlyOwner`
- [ ] `check_DisableUpgrades_OnlyOwner`
- [ ] `check_DisableUpgradesMonotonic` — after `disableUpgrades()`, any
      subsequent call to `_authorizeUpgrade` reverts for every caller / impl
- [ ] `check_IsAppAllowed_DecisionTable(IAppAuth.AppBootInfo bootInfo)` —
      prove the boolean formula:
      ```
      isAppAllowed(b) == (true, "")
        ⟺ (!requireTcbUpToDate || b.tcbStatus == "UpToDate")
          && allowedComposeHashes[b.composeHash]
          && (allowAnyDevice || allowedDeviceIds[b.deviceId])
      ```
- [ ] `check_Initialize5Arg_DefaultsTcbToFalse` — after the legacy 5-arg
      initializer for any inputs, `requireTcbUpToDate == false`
- [ ] `check_Initialize6Arg_HonorsTcbFlag(bool flag, ...)` — after the 6-arg
      initializer, `requireTcbUpToDate == flag`

### `DstackKms` symbolic properties (`test/DstackKms.symbolic.t.sol`)

- [ ] `check_SetKmsInfo_OnlyOwner`
- [ ] `check_SetGatewayAppId_OnlyOwner`
- [ ] `check_AddKmsAggregatedMr_OnlyOwner` and `Remove…_OnlyOwner`
- [ ] `check_AddKmsDevice_OnlyOwner` and `Remove…_OnlyOwner`
- [ ] `check_AddOsImageHash_OnlyOwner` and `Remove…_OnlyOwner`
- [ ] `check_SetAppImplementation_OnlyOwner`
- [ ] `check_RegisterApp_OnlyOwner` and `Unregister…_OnlyOwner`
- [ ] `check_DeployAndRegisterApp_5arg_DefaultsTcbToFalse` — 5-arg factory
      always sets `requireTcbUpToDate = false` on the new app
- [ ] `check_DeployAndRegisterApp_6arg_HonorsTcbFlag` — 6-arg factory
      propagates the flag exactly
- [ ] `check_DeployAndRegisterApp_RegistersAtomically` — if the call
      returns, both `registeredApps[appId]` is true *and* the appId is a
      live UUPS proxy with the configured initial state
- [ ] `check_IsAppAllowed_RejectsUnknownOsImage` — if
      `!allowedOsImages[b.osImageHash]`, the result is `(false, …)` and
      no delegation to the app happens
- [ ] `check_IsKmsAllowed_RequiresAllowedMr` and other short-circuit cases

### Coverage acceptance

A property "passes" only when Halmos returns `[PASS]` without `--symbolic-storage`
exclusions. Properties that solve only under bounded loops should be flagged.

### Findings from the initial run

- **`DstackKms.registerApp` is intentionally permissionless** (confirmed
  by the dstack team). The Halmos counterexample on
  `check_RegisterApp_OnlyOwner` reflects design, not a bug: any non-zero
  address can be registered by anyone. Authorization is still gated
  downstream by the owner-controlled `allowedOsImages` whitelist and by
  the registered app's own `isAppAllowed` logic, so registration alone
  confers no privilege. The contract now carries a natspec block on
  `registerApp` stating this explicitly, and the symbolic suite asserts
  the actual behavior via `check_RegisterApp_AnyCallerCanRegisterNonZeroAddress`
  + `check_RegisterApp_RejectsZeroAddress`.

- **TCB status compare is byte-exact** (confirmed). The contract uses
  `keccak256(abi.encodePacked(bootInfo.tcbStatus)) != keccak256(abi.encodePacked("UpToDate"))`,
  which by the cryptographic-collision-resistance assumption is true
  iff the byte sequences differ. The off-chain attestation pipeline must
  emit the exact 8-byte ASCII string `"UpToDate"` — no case variations,
  trailing nulls, or whitespace. Proven by
  `check_TcbStatus_OnlyExactUpToDateAccepted` (symbolic over all
  bounded strings) plus the concrete `check_TcbStatus_RejectsLowercase` /
  `_RejectsTrailingChars` cases.

- **Two-step ownership transfer adopted.** Both contracts now inherit
  `Ownable2StepUpgradeable` instead of `OwnableUpgradeable`. The new
  storage uses ERC-7201 namespaced slots, so existing UUPS proxies can
  be safely upgraded to the new impl (no slot collision; the pending-
  owner slot is zero-initialized on first upgrade). `transferOwnership`
  no longer immediately transfers — the proposed owner must call
  `acceptOwnership` to complete the transfer, eliminating the typo-bricks-
  contract risk on the single-step variant.

**Effort:** ~1 focused day. **Owner:** _tbd_.

## Layer 3 — Certora (deferred)

Deferred until a security review budget exists. CVL specs are 3-5× the size of
Halmos tests, require team licenses, and overlap with Halmos coverage for
authorization-style properties.

If we revisit, target the same invariants as Layer 2 but add:

- Storage-layout safety across upgrades (especially the
  `@custom:oz-renamed-from tproxyAppId` rename — Certora's storage diff is
  stronger than the OZ Foundry plugin's)
- Cross-contract invariants spanning `DstackKms` ↔ `DstackApp`

## What's intentionally not in scope

- **CI gating of Slither / Halmos.** Symbolic execution is slow, solver-
  version-sensitive, and produces non-actionable noise as a PR gate.
  Run locally during development; treat these as design checks rather
  than blocking lints.
- **Echidna** — overlaps with Foundry's built-in fuzzer (already runs 10k
  iterations under `FOUNDRY_PROFILE=ci` in `.github/workflows/foundry-test.yml`).
- **Manticore / Mythril** — bytecode-level tools, slow, awkward with our
  forge artifacts.
- **Scribble** — runtime assertions, redundant with our `assert` + Foundry
  test approach.

## Status

| Layer | Status | PR |
|-------|--------|----|
| 0. Slither | done (0 findings) | this branch |
| 1. SMTChecker | deferred (see above) | — |
| 2. Halmos (DstackApp) | done (11 properties) | this branch |
| 2. Halmos (DstackKms) | done (14 properties) | this branch |
| 3. Certora | deferred | — |

Update this table as PRs land.

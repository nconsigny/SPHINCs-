// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardineroFrameAccount — EIP-8141 Frame account, pure PQ
/// @notice Storage layout matches JardinFrameAccount.sol so the proxy
///         bytecode and deployer script continue to work without changes:
///             slot 0: t0Verifier      (was c11Verifier)
///             slot 1: forscVerifier
///             slot 2: t0PkSeed        (was masterPkSeed)
///             slot 3: t0PkRoot        (was masterPkRoot)
///             slot 4: owner
///
/// Frame tx layouts:
///   Type 1 (register):  VERIFY[sigHash‖01‖sub‖T0sig] → SENDER[registerSlot(sub)]
///   Type 2 (compact):   VERIFY[sigHash‖02‖sub‖FORSsig] → SENDER[execute(...)]
///   Stateless fallback: VERIFY[sigHash‖01‖0‖0‖T0sig] → SENDER[execute(...)]
///
/// Onboarding avoids C11 entirely — T0 keygen builds only the top-layer
/// XMSS (4 WOTS+C keypairs, ~40× faster on hardware than C11).
contract JardineroFrameAccount {

    address public t0Verifier;     // slot 0 (reused from old c11Verifier slot)
    address public forscVerifier;  // slot 1
    bytes32 public t0PkSeed;       // slot 2
    bytes32 public t0PkRoot;       // slot 3
    address public owner;          // slot 4

    /// @notice Sub-key slots: keccak256(subPkSeed, subPkRoot) => 1 (registered flag)
    mapping(bytes32 => uint256) public slots;

    error InvalidSignatureType();
    error SlotAlreadyRegistered();
    error UnregisteredSlot();
    error NotSelf();

    constructor(
        address _t0Verifier,
        address _forscVerifier,
        bytes32 _t0PkSeed,
        bytes32 _t0PkRoot,
        address _owner
    ) {
        t0Verifier = _t0Verifier;
        forscVerifier = _forscVerifier;
        t0PkSeed = _t0PkSeed;
        t0PkRoot = _t0PkRoot;
        owner = _owner;
    }

    // ═══════════════════════════════════════════════════════════
    //  VERIFY frame entry: fallback receives sigHash(32) || sig(N)
    //  Pure read-only — no SSTOREs. Proxy emits APPROVE after.
    // ═══════════════════════════════════════════════════════════

    fallback(bytes calldata input) external returns (bytes memory) {
        require(input.length > 65, InvalidSignatureType());

        bytes32 sigHash = bytes32(input[:32]);
        bytes calldata sig = input[32:];
        uint8 sigType = uint8(sig[0]);

        if (sigType == 0x01) {
            // Type 1: T0 verify against master keys. Sub-key bytes in the sig
            // describe what will be registered in the SENDER frame; verification
            // itself ignores them (master T0 keys authorize the registration).
            (bool ok, bytes memory res) = t0Verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    t0PkSeed, t0PkRoot, sigHash, sig[33:]
                )
            );
            require(ok && res.length >= 32 && abi.decode(res, (bool)), "T0 verify failed");

        } else if (sigType == 0x02) {
            // Type 2: FORS+C compact — verify slot registration + signature
            bytes16 subSeed = bytes16(sig[1:17]);
            bytes16 subRoot = bytes16(sig[17:33]);
            bytes32 key = keccak256(abi.encodePacked(subSeed, subRoot));
            require(slots[key] != 0, UnregisteredSlot());

            (bool ok, bytes memory res) = forscVerifier.staticcall(
                abi.encodeWithSignature(
                    "verifyForsC(bytes32,bytes32,bytes32,bytes)",
                    bytes32(subSeed), bytes32(subRoot), sigHash, sig[33:]
                )
            );
            require(ok && res.length >= 32 && abi.decode(res, (bool)), "FORS+C verify failed");

        } else {
            revert InvalidSignatureType();
        }

        return "";
    }

    // ═══════════════════════════════════════════════════════════
    //  SENDER frame entries: state-modifying operations
    // ═══════════════════════════════════════════════════════════

    function registerSlot(bytes16 subSeed, bytes16 subRoot) external {
        bytes32 key = keccak256(abi.encodePacked(subSeed, subRoot));
        require(slots[key] == 0, SlotAlreadyRegistered());
        slots[key] = 1;
    }

    function execute(address dest, uint256 value, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        require(success, "exec failed");
        return result;
    }

    function rotateT0Keys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotSelf());
        t0PkSeed = newPkSeed;
        t0PkRoot = newPkRoot;
    }

    function rotateVerifiers(address newT0, address newForsc) external {
        require(msg.sender == address(this), NotSelf());
        t0Verifier = newT0;
        forscVerifier = newForsc;
    }

    function rotateOwner(address newOwner) external {
        require(msg.sender == address(this), NotSelf());
        require(newOwner != address(0));
        owner = newOwner;
    }

    receive() external payable {}
}

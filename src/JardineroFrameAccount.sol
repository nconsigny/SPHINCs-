// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardineroFrameAccount — EIP-8141 Frame account, pure PQ (SPX variant)
/// @notice Storage layout matches the legacy JardinFrameAccount/JardineroFrameAccount
///         so the proxy bytecode (build_proxy_bytecode) and deployer keep working:
///             slot 0: spxVerifier     (was t0Verifier / c11Verifier)
///             slot 1: forscVerifier
///             slot 2: spxPkSeed       (was t0PkSeed / masterPkSeed)
///             slot 3: spxPkRoot       (was t0PkRoot / masterPkRoot)
///             slot 4: owner
///
/// Frame tx layouts:
///   Type 1 (register):  VERIFY[sigHash‖01‖sub‖SPXsig] → SENDER[registerSlot(sub)]
///   Type 2 (compact):   VERIFY[sigHash‖02‖sub‖FORSsig] → SENDER[execute(...)]
///   Stateless fallback: VERIFY[sigHash‖01‖0‖0‖SPXsig] → SENDER[execute(...)]
///
/// Plain SPHINCS+ (SPX) replaces T0/C11 as the registration-path verifier.
/// Signature length: 6512 B. Signing cost: ~36.6K keccak calls.
contract JardineroFrameAccount {

    address public spxVerifier;    // slot 0
    address public forscVerifier;  // slot 1
    bytes32 public spxPkSeed;      // slot 2
    bytes32 public spxPkRoot;      // slot 3
    address public owner;          // slot 4

    /// @notice Sub-key slots: keccak256(subPkSeed, subPkRoot) => 1 (registered flag)
    mapping(bytes32 => uint256) public slots;

    error InvalidSignatureType();
    error SlotAlreadyRegistered();
    error UnregisteredSlot();
    error NotSelf();

    constructor(
        address _spxVerifier,
        address _forscVerifier,
        bytes32 _spxPkSeed,
        bytes32 _spxPkRoot,
        address _owner
    ) {
        spxVerifier = _spxVerifier;
        forscVerifier = _forscVerifier;
        spxPkSeed = _spxPkSeed;
        spxPkRoot = _spxPkRoot;
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
            // Type 1: SPX verify against master keys. Sub-key bytes in the sig
            // describe what will be registered in the SENDER frame; verification
            // itself ignores them (master SPX keys authorize the registration).
            (bool ok, bytes memory res) = spxVerifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    spxPkSeed, spxPkRoot, sigHash, sig[33:]
                )
            );
            require(ok && res.length >= 32 && abi.decode(res, (bool)), "SPX verify failed");

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

    function rotateSpxKeys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotSelf());
        spxPkSeed = newPkSeed;
        spxPkRoot = newPkRoot;
    }

    function rotateVerifiers(address newSpx, address newForsc) external {
        require(msg.sender == address(this), NotSelf());
        spxVerifier = newSpx;
        forscVerifier = newForsc;
    }

    function rotateOwner(address newOwner) external {
        require(msg.sender == address(this), NotSelf());
        require(newOwner != address(0));
        owner = newOwner;
    }

    receive() external payable {}
}

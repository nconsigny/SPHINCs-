// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinFrameAccount — EIP-8141 Frame account with JARDÍN (pure PQ)
/// @notice Split architecture per EIP-8141:
///   VERIFY frame (STATICCALL-like, no writes): signature verification → APPROVE
///   SENDER frame (full access): slot registration + user execution
///
/// Slot key is keccak256(subPkSeed, subPkRoot); registered slots store 1.
/// The random `r` used to derive the sub-key never appears on-chain.
///
/// Frame tx layouts:
///   Type 1 (register):  VERIFY[sigHash||01||sub||C11sig] → SENDER[registerSlot(sub)]
///   Type 2 (compact):   VERIFY[sigHash||02||sub||FORSsig] → SENDER[execute(...)]
///   Stateless fallback: VERIFY[sigHash||01||0||0||C11sig] → SENDER[execute(...)]
///
/// The bytecode proxy DELEGATECALLs here, then APPROVEs if in VERIFY mode.
contract JardinFrameAccount {

    address public c11Verifier;    // slot 0
    address public forscVerifier;  // slot 1
    bytes32 public masterPkSeed;   // slot 2
    bytes32 public masterPkRoot;   // slot 3
    address public owner;          // slot 4

    /// @notice Sub-key slots: keccak256(subPkSeed, subPkRoot) => 1 (registered flag)
    mapping(bytes32 => uint256) public slots;

    error InvalidSignatureType();
    error SlotAlreadyRegistered();
    error UnregisteredSlot();
    error NotSelf();

    constructor(
        address _c11Verifier,
        address _forscVerifier,
        bytes32 _masterPkSeed,
        bytes32 _masterPkRoot,
        address _owner
    ) {
        c11Verifier = _c11Verifier;
        forscVerifier = _forscVerifier;
        masterPkSeed = _masterPkSeed;
        masterPkRoot = _masterPkRoot;
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
            // Type 1: C11 stateless — verify only, no slot write
            (bool ok, bytes memory res) = c11Verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    masterPkSeed, masterPkRoot, sigHash, sig[33:]
                )
            );
            require(ok && res.length >= 32 && abi.decode(res, (bool)), "C11 verify failed");

        } else if (sigType == 0x02) {
            // Type 2: FORS+C compact — verify slot + signature
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

    /// @notice Register a FORS+C sub-key slot (called in SENDER frame after Type 1 VERIFY)
    function registerSlot(bytes16 subSeed, bytes16 subRoot) external {
        bytes32 key = keccak256(abi.encodePacked(subSeed, subRoot));
        require(slots[key] == 0, SlotAlreadyRegistered());
        slots[key] = 1;
    }

    /// @notice Execute arbitrary call (called in SENDER frame)
    function execute(address dest, uint256 value, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        require(success, "exec failed");
        return result;
    }

    /// @notice Rotate master SPHINCs- keys
    function rotateMasterKeys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotSelf());
        masterPkSeed = newPkSeed;
        masterPkRoot = newPkRoot;
    }

    /// @notice Rotate verifier addresses
    function rotateVerifiers(address newC11, address newForsc) external {
        require(msg.sender == address(this), NotSelf());
        c11Verifier = newC11;
        forscVerifier = newForsc;
    }

    /// @notice Rotate owner
    function rotateOwner(address newOwner) external {
        require(msg.sender == address(this), NotSelf());
        require(newOwner != address(0));
        owner = newOwner;
    }

    receive() external payable {}
}

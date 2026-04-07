// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

interface IMerkleKernel {
    function configureRoot(uint256 newRoot) external;
    function currentRoot() external returns (uint256);
    function previewPath(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        bool sibling0OnLeft,
        bool sibling1OnLeft,
        bool sibling2OnLeft,
        bool sibling3OnLeft
    ) external returns (uint256);
    function previewPackedPath(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        uint256 directions
    ) external returns (uint256);
    function verifyPath(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        bool sibling0OnLeft,
        bool sibling1OnLeft,
        bool sibling2OnLeft,
        bool sibling3OnLeft
    ) external returns (bool);
    function verifyPackedPath(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        uint256 directions
    ) external returns (bool);
}

contract MerkleKernelVerityTest is Test {
    uint256 internal constant SAMPLE_LEAF = 7;
    uint256 internal constant SAMPLE_SIBLING0 = 11;
    uint256 internal constant SAMPLE_SIBLING1 = 13;
    uint256 internal constant SAMPLE_SIBLING2 = 17;
    uint256 internal constant SAMPLE_SIBLING3 = 19;

    function setUp() public {
        string[] memory compileInputs = new string[](2);
        compileInputs[0] = "python3";
        compileInputs[1] = "verity/scripts/compile_merkle_kernel.py";
        vm.ffi(compileInputs);
    }

    function test_configureCurrentRoot_roundtrip() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 configuredRoot = 123456789;

        kernel.configureRoot(configuredRoot);

        assertEq(kernel.currentRoot(), configuredRoot, "currentRoot should expose storage slot 0");
    }

    function test_previewPath_matchesReferenceExample() public {
        IMerkleKernel kernel = _deployKernel();

        uint256 got = kernel.previewPath(
            SAMPLE_LEAF,
            SAMPLE_SIBLING0,
            SAMPLE_SIBLING1,
            SAMPLE_SIBLING2,
            SAMPLE_SIBLING3,
            false,
            true,
            false,
            true
        );

        assertEq(
            got,
            _previewReference(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                false,
                true,
                false,
                true
            ),
            "Verity previewPath should match the kernel model"
        );
    }

    function test_verifyPath_acceptsMatchingExample() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 acceptedRoot = _previewReference(
            SAMPLE_LEAF,
            SAMPLE_SIBLING0,
            SAMPLE_SIBLING1,
            SAMPLE_SIBLING2,
            SAMPLE_SIBLING3,
            false,
            true,
            false,
            true
        );

        kernel.configureRoot(acceptedRoot);

        assertTrue(
            kernel.verifyPath(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                false,
                true,
                false,
                true
            ),
            "verifyPath should accept the witness used to configure the root"
        );
        assertEq(kernel.currentRoot(), acceptedRoot, "verifyPath must preserve state");
    }

    function test_verifyPath_rejectsWrongDirectionExample() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 acceptedRoot = _previewReference(
            SAMPLE_LEAF,
            SAMPLE_SIBLING0,
            SAMPLE_SIBLING1,
            SAMPLE_SIBLING2,
            SAMPLE_SIBLING3,
            false,
            true,
            false,
            true
        );

        kernel.configureRoot(acceptedRoot);

        assertFalse(
            kernel.verifyPath(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                true,
                true,
                false,
                true
            ),
            "changing the witness path should be rejected"
        );
        assertEq(kernel.currentRoot(), acceptedRoot, "failed verification must preserve state");
    }

    function test_previewPackedPath_matchesReferenceExample() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 directions = 10;

        uint256 got = kernel.previewPackedPath(
            SAMPLE_LEAF,
            SAMPLE_SIBLING0,
            SAMPLE_SIBLING1,
            SAMPLE_SIBLING2,
            SAMPLE_SIBLING3,
            directions
        );

        assertEq(
            got,
            _previewReferencePacked(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                directions
            ),
            "previewPackedPath should decode the witness directions from the low nibble"
        );
    }

    function test_verifyPackedPath_acceptsMatchingExample() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 directions = 10;
        uint256 acceptedRoot = _previewReferencePacked(
            SAMPLE_LEAF,
            SAMPLE_SIBLING0,
            SAMPLE_SIBLING1,
            SAMPLE_SIBLING2,
            SAMPLE_SIBLING3,
            directions
        );

        kernel.configureRoot(acceptedRoot);

        assertTrue(
            kernel.verifyPackedPath(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                directions
            ),
            "verifyPackedPath should accept the decoded witness used to configure the root"
        );
        assertEq(kernel.currentRoot(), acceptedRoot, "verifyPackedPath must preserve state");
    }

    function test_verifyPackedPath_rejectsNonCanonicalDirections() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 lowNibble = 10;
        uint256 noisyDirections = lowNibble | (uint256(1) << 200);
        uint256 acceptedRoot = _previewReferencePacked(
            SAMPLE_LEAF,
            SAMPLE_SIBLING0,
            SAMPLE_SIBLING1,
            SAMPLE_SIBLING2,
            SAMPLE_SIBLING3,
            lowNibble
        );

        kernel.configureRoot(acceptedRoot);

        assertFalse(
            kernel.verifyPackedPath(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                noisyDirections
            ),
            "verifyPackedPath should reject non-canonical packed directions"
        );
        assertEq(kernel.currentRoot(), acceptedRoot, "rejected packed verification must preserve state");
    }

    function test_previewPackedPath_ignoresHighDirectionBits() public {
        IMerkleKernel kernel = _deployKernel();
        uint256 lowNibble = 10;
        uint256 noisyDirections = lowNibble | (uint256(1) << 200);

        assertEq(
            kernel.previewPackedPath(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                noisyDirections
            ),
            kernel.previewPackedPath(
                SAMPLE_LEAF,
                SAMPLE_SIBLING0,
                SAMPLE_SIBLING1,
                SAMPLE_SIBLING2,
                SAMPLE_SIBLING3,
                lowNibble
            ),
            "only the low 4 direction bits should affect decoding"
        );
    }

    function testFuzz_previewPath_matchesReference(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        bool sibling0OnLeft,
        bool sibling1OnLeft,
        bool sibling2OnLeft,
        bool sibling3OnLeft
    ) public {
        IMerkleKernel kernel = _deployKernel();

        uint256 expected = _previewReference(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            sibling0OnLeft,
            sibling1OnLeft,
            sibling2OnLeft,
            sibling3OnLeft
        );

        uint256 got = kernel.previewPath(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            sibling0OnLeft,
            sibling1OnLeft,
            sibling2OnLeft,
            sibling3OnLeft
        );

        assertEq(got, expected, "previewPath should equal the reference model for all inputs");
    }

    function testFuzz_verifyPath_matchesReference(
        uint256 root,
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        bool sibling0OnLeft,
        bool sibling1OnLeft,
        bool sibling2OnLeft,
        bool sibling3OnLeft
    ) public {
        IMerkleKernel kernel = _deployKernel();
        uint256 candidate = _previewReference(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            sibling0OnLeft,
            sibling1OnLeft,
            sibling2OnLeft,
            sibling3OnLeft
        );

        kernel.configureRoot(root);

        bool got = kernel.verifyPath(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            sibling0OnLeft,
            sibling1OnLeft,
            sibling2OnLeft,
            sibling3OnLeft
        );

        assertEq(got, candidate == root, "verifyPath should accept exactly matching roots");
        assertEq(kernel.currentRoot(), root, "verifyPath must not mutate the configured root");
    }

    function testFuzz_previewPackedPath_matchesReference(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        uint256 directions
    ) public {
        IMerkleKernel kernel = _deployKernel();
        uint256 expected = _previewReferencePacked(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            directions
        );

        assertEq(
            kernel.previewPackedPath(leaf, sibling0, sibling1, sibling2, sibling3, directions),
            expected,
            "previewPackedPath should match the packed witness reference model"
        );
    }

    function testFuzz_verifyPackedPath_matchesReference(
        uint256 root,
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        uint256 directions
    ) public {
        IMerkleKernel kernel = _deployKernel();
        uint256 candidate = _previewReferencePacked(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            directions
        );

        kernel.configureRoot(root);

        bool got = kernel.verifyPackedPath(leaf, sibling0, sibling1, sibling2, sibling3, directions);

        assertEq(
            got,
            _packedDirectionsCanonical(directions) && candidate == root,
            "verifyPackedPath should accept only canonical packed witnesses with matching roots"
        );
        assertEq(kernel.currentRoot(), root, "verifyPackedPath must not mutate the configured root");
    }

    function _deployKernel() internal returns (IMerkleKernel kernel) {
        string[] memory compileInputs = new string[](3);
        compileInputs[0] = "python3";
        compileInputs[1] = "verity/scripts/compile_merkle_kernel.py";
        compileInputs[2] = "--stdout";
        bytes memory initCode = vm.ffi(compileInputs);
        address deployed;

        assembly {
            deployed := create(0, add(initCode, 0x20), mload(initCode))
        }

        require(deployed != address(0), "MerkleKernel deployment failed");
        kernel = IMerkleKernel(deployed);
    }

    function _previewReference(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        bool sibling0OnLeft,
        bool sibling1OnLeft,
        bool sibling2OnLeft,
        bool sibling3OnLeft
    ) internal pure returns (uint256) {
        uint256 level0 = _step(leaf, sibling0, sibling0OnLeft);
        uint256 level1 = _step(level0, sibling1, sibling1OnLeft);
        uint256 level2 = _step(level1, sibling2, sibling2OnLeft);
        return _step(level2, sibling3, sibling3OnLeft);
    }

    function _previewReferencePacked(
        uint256 leaf,
        uint256 sibling0,
        uint256 sibling1,
        uint256 sibling2,
        uint256 sibling3,
        uint256 directions
    ) internal pure returns (uint256) {
        return _previewReference(
            leaf,
            sibling0,
            sibling1,
            sibling2,
            sibling3,
            _directionBit(directions, 0),
            _directionBit(directions, 1),
            _directionBit(directions, 2),
            _directionBit(directions, 3)
        );
    }

    function _directionBit(uint256 directions, uint256 index) internal pure returns (bool) {
        return ((directions >> index) & 1) != 0;
    }

    function _packedDirectionsCanonical(uint256 directions) internal pure returns (bool) {
        return (directions >> 4) == 0;
    }

    function _step(uint256 acc, uint256 sibling, bool siblingOnLeft) internal pure returns (uint256) {
        return siblingOnLeft ? _compress(sibling, acc) : _compress(acc, sibling);
    }

    function _compress(uint256 left, uint256 right) internal pure returns (uint256) {
        unchecked {
            return left * 65537 + right * 257 + 97;
        }
    }
}

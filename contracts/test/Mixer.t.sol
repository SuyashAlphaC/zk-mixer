//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;
import {Test, console} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/Verifier.sol";
import {IncrementalMerkleTree, Poseidon2} from "../src/IncrementalMerkleTree.sol";
import {Mixer} from "../src/Mixer.sol";

contract MixerTest is Test {
    Poseidon2 public hasher;
    HonkVerifier public verifier;
    Mixer public mixer;
    uint32 public constant TREE_DEPTH = 20;
    address public receiver = makeAddr("receiver");

    function setUp() public {
        hasher = new Poseidon2();
        verifier = new HonkVerifier();
        mixer = new Mixer(verifier,TREE_DEPTH, hasher);
    }

    function _getCommitment() public returns(bytes32 _commitment) {
        string[] memory input = new string[](3);

        input[0] = "npx";
        input[1] = "tsx";
        input[2] = "js-scripts/generateCommitment.ts";
        bytes memory result = vm.ffi(input);
       _commitment =  abi.decode(result, (bytes32));
    }
    function testDeposit() public {
        bytes32 _commitment = _getCommitment();
        console.log("Commitment: ");
        console.logBytes32(_commitment);
        vm.expectEmit(true, false, false, true);
        emit Mixer.Deposit(_commitment, 0, block.timestamp);
        mixer.deposit{value : mixer.DENOMINATION()}(_commitment);

    }
}

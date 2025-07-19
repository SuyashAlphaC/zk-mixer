//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;
import {Test, console} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/Verifier.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
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

    function _getCommitment() public returns(bytes32 _commitment, bytes32 _nullifier, bytes32 _secret) {
        string[] memory input = new string[](3);

        input[0] = "npx";
        input[1] = "tsx";
        input[2] = "js-scripts/generateCommitment.ts";
        bytes memory result = vm.ffi(input);
       (_commitment, _nullifier, _secret) =  abi.decode(result, (bytes32, bytes32, bytes32));
    }

    function _getProof(bytes32[] memory leaves, bytes32 _nullifier, bytes32 _secret, address _recipient) public returns(bytes memory _proof , bytes32[] memory _publicInputs) {
        string[] memory input = new string[](6 + leaves.length);
        input[0] = "npx";
        input[1] = "tsx";
        input[2] = "js-scripts/generateProof.ts";
        input[3] = vm.toString(_nullifier);
        input[4] = vm.toString(_secret);
        input[5] = vm.toString(bytes32(uint256(uint160(_recipient))));

        for(uint256 i = 0; i < leaves.length; i ++ ) {
            input[6 + i] = vm.toString(leaves[i]);
        }

        bytes memory result = vm.ffi(input);
        (_proof, _publicInputs) = abi.decode(result, (bytes, bytes32[]));
    } 
    function testDeposit() public {
        (bytes32 _commitment, bytes32 _nullifier, bytes32 _secret) = _getCommitment();
        console.log("Commitment: ");
        console.logBytes32(_commitment);
        vm.expectEmit(true, false, false, true);
        emit Mixer.Deposit(_commitment, 0, block.timestamp);
        mixer.deposit{value : mixer.DENOMINATION()}(_commitment);

    }

    function testWithdraw() public {
        (bytes32 _commitment, bytes32 _nullifier, bytes32 _secret) = _getCommitment();
        console.log("Commitment: ");
        console.logBytes32(_commitment);
        vm.expectEmit(true, false, false, true);
        emit Mixer.Deposit(_commitment, 0, block.timestamp);
        mixer.deposit{value : mixer.DENOMINATION()}(_commitment);  
        
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _commitment;

        (bytes memory _proof, bytes32[] memory _publicInputs) = _getProof(leaves, _nullifier, _secret, receiver);
        console.log("Proof : ");
        console.logBytes(_proof);

        assertEq(address(mixer).balance, mixer.DENOMINATION());
        assertEq(receiver.balance, 0);
        mixer.withdraw(_proof, _publicInputs[0], _publicInputs[1], payable(address(uint160(uint256(_publicInputs[2])))));
        assertEq(address(mixer).balance, 0);
        assertEq(receiver.balance, mixer.DENOMINATION());
    }
}

//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;
import {IncrementalMerkleTree, Poseidon2} from "./IncrementalMerkleTree.sol";
contract Mixer is IncrementalMerkleTree {
    IVerifier public immutable i_verifier;

    mapping(bytes32 => bool) public s_commitments;
    uint256 public constant DENOMINATION = 0.001 ether;

    mapping(bytes32 =>bool) public s_nullifierHashes;
    
    event Deposit(bytes32 commitment);

    

    error Mixer__InvalidDenomination(uint256 ethDeposited, uint256 denomination);
    error Mixer__UnknownRoot(bytes32 _root);
    error Mixer__NullifierAlreadyUsed(bytes32 _nullifierHash);
    error Mixer__CommitmentAlreadySaved(bytes32 commitment, uint32 index, uint256 timestamp);
    constructor(IVerifier _verifier, uint32 _treeDepth,  Poseidon2 _hasher)  IncrementalMerkleTree(_treeDepth, _hasher) {
        i_verifier = _verifier;
    }

    function deposit(bytes32 _commitment) external payable{
        if(s_commitments[_commitment]) {
            revert Mixer__CommitmentAlreadySaved(_commitment);
        }

        if(msg.value != DENOMINATION) {
            revert Mixer__InvalidEthDeposition(msg.value, DENOMINATION);
        }
        uint32 inserttedIndex = _insert(commitment);
        s_commitments[_commitment] = true;

        emit Deposit(commitment,insertedIndex, block.timestamp);
    }

    function withdraw(bytes32 proof , bytes32 _root , bytes32 _nullifierHash) external {
        if(s_root != _root) {
            revert Mixer__UnknownRoot(_root);
        }

        if(s_nullifierHashes[_nullifierHash]) {
            revert Mixer__NullifierAlreadyUsed(_nullifierHash);
        }

        s_nullifierHashes[_nullifierHash] = true;
    }
}
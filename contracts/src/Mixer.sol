//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;
import {IVerifier} from "./Verifier.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IncrementalMerkleTree, Poseidon2} from "./IncrementalMerkleTree.sol";
contract Mixer is IncrementalMerkleTree, ReentrancyGuard {
    IVerifier public immutable i_verifier;

    mapping(bytes32 => bool) public s_commitments;
    uint256 public constant DENOMINATION = 0.001 ether;

    mapping(bytes32 =>bool) public s_nullifierHashes;
    
    event Deposit(bytes32 indexed commitment, uint32 index, uint256 timestamp);
    event Withdraw(address payable indexed_receiver, bytes32 nullifierHash, uint256 amount);

    error Mixer__TransferFailed();
    error Mixer__InvalidProof();
    error Mixer__InvalidEthDeposition(uint256 ethSent, uint256 denomination);
    error Mixer__InvalidDenomination(uint256 ethDeposited, uint256 denomination);
    error Mixer__UnknownRoot(bytes32 _root);
    error Mixer__NullifierAlreadyUsed(bytes32 _nullifierHash);
    error Mixer__CommitmentAlreadySaved(bytes32 commitment);
    constructor(IVerifier _verifier, uint32 _treeDepth,  Poseidon2 _hasher)  IncrementalMerkleTree(_treeDepth, _hasher) {
        i_verifier = _verifier;
    }

    function deposit(bytes32 _commitment) external payable nonReentrant{
        if(s_commitments[_commitment]) {
            revert Mixer__CommitmentAlreadySaved(_commitment);
        }

        if(msg.value != DENOMINATION) {
            revert Mixer__InvalidEthDeposition(msg.value, DENOMINATION);
        }
        uint32 insertedIndex = _insert(_commitment);
        s_commitments[_commitment] = true;

        emit Deposit(_commitment,insertedIndex, block.timestamp);
    }

    function withdraw(bytes memory proof , bytes32 _root , bytes32 _nullifierHash, address payable _receiver) external  nonReentrant{
        if(!isKnownRoot(_root)) {
            revert Mixer__UnknownRoot(_root);
        }

        if(s_nullifierHashes[_nullifierHash]) {
            revert Mixer__NullifierAlreadyUsed(_nullifierHash);
        }
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = _root;
        publicInputs[1] = _nullifierHash;
        publicInputs[2] = bytes32(uint256(uint160(address(_receiver))));

        if(!i_verifier.verify(proof, publicInputs)) {
            revert Mixer__InvalidProof();
        }

        s_nullifierHashes[_nullifierHash] = true;

        (bool success, ) = _receiver.call{value: DENOMINATION}("");
        if(!success) {
            revert Mixer__TransferFailed();
        }

        emit Withdraw(_receiver, _nullifierHash, DENOMINATION);
    }
}
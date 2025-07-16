//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;

contract Mixer {
    IVerifier public immutable i_verifier;

    mapping(bytes32 => bool) public s_commitments;
    uint256 public constant DENOMINATION = 0.001 ether;
    

    error Mixer__InvalidDenomination(uint256 ethDeposited, uint256 denomination);
    error Mixer__CommitmentAlreadySaved(bytes32 commitment);
    constructor(IVerifier _verifier) {
        i_verifier = _verifier;
    }

    function deposit(bytes32 _commitment) public payable{
        if(s_commitments[_commitment]) {
            revert Mixer__CommitmentAlreadySaved(_commitment);
        }

        if(msg.value != DENOMINATION) {
            revert Mixer__InvalidEthDeposition(msg.value, DENOMINATION);
        }

        s_commitments[_commitment] = true;
    }
}
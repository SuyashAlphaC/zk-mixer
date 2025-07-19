//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;

import {IVerifier} from "./Verifier.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IncrementalMerkleTree, Poseidon2} from "./IncrementalMerkleTree.sol";

/**
 * @title Mixer
 * @author Suyash Agrawal
 * @notice A privacy-preserving cryptocurrency mixer inspired by Tornado Cash
 * @dev This contract allows users to deposit ETH with a commitment and later withdraw
 *      it to a different address using zero-knowledge proofs. The mixer uses:
 *      - Incremental Merkle Trees to track commitments
 *      - Zero-knowledge proofs (via Noir) to prove ownership without revealing identity
 *      - Nullifiers to prevent double-spending
 *      
 *      Privacy Flow:
 *      1. User generates secret + nullifier, computes commitment = hash(secret, nullifier)
 *      2. User deposits ETH along with commitment
 *      3. Commitment is added to Merkle tree
 *      4. Later, user generates ZK proof knowing secret, nullifier, and merkle path
 *      5. User withdraws to any address using the proof and nullifier
 */
contract Mixer is IncrementalMerkleTree, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Fixed denomination for all deposits/withdrawals (0.001 ETH)
    /// @dev All deposits must be exactly this amount to maintain anonymity set
    uint256 public constant DENOMINATION = 0.001 ether;

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE VARIABLES
    //////////////////////////////////////////////////////////////*/
    
    /// @notice The zero-knowledge proof verifier contract
    /// @dev Used to verify Noir/Plonk proofs during withdrawal
    IVerifier public immutable i_verifier;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Tracks which commitments have been deposited
    /// @dev Prevents duplicate commitments from being accepted
    mapping(bytes32 => bool) public s_commitments;
    
    /// @notice Tracks which nullifiers have been used
    /// @dev Prevents double-spending by ensuring each nullifier is used only once
    mapping(bytes32 => bool) public s_nullifierHashes;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Emitted when a deposit is made
     * @param commitment The commitment hash that was deposited
     * @param index The leaf index where the commitment was inserted in the Merkle tree
     * @param timestamp The block timestamp when the deposit occurred
     */
    event Deposit(bytes32 indexed commitment, uint32 index, uint256 timestamp);
    
    /**
     * @notice Emitted when a withdrawal is made
     * @param indexed_receiver The address that received the withdrawn funds
     * @param nullifierHash The nullifier hash used to prevent double-spending
     * @param amount The amount withdrawn (always DENOMINATION)
     */
    event Withdraw(address payable indexed indexed_receiver, bytes32 nullifierHash, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/
    
    /// @dev Thrown when ETH transfer fails during withdrawal
    error Mixer__TransferFailed();
    
    /// @dev Thrown when the zero-knowledge proof verification fails
    error Mixer__InvalidProof();
    
    /// @dev Thrown when deposit amount doesn't match required denomination
    /// @param ethSent The amount of ETH sent with the transaction
    /// @param denomination The required denomination amount
    error Mixer__InvalidEthDeposition(uint256 ethSent, uint256 denomination);
    
    /// @dev Thrown when withdrawal amount doesn't match denomination (legacy error)
    /// @param ethDeposited The deposited amount
    /// @param denomination The required denomination amount
    error Mixer__InvalidDenomination(uint256 ethDeposited, uint256 denomination);
    
    /// @dev Thrown when the provided Merkle root is not in the known roots history
    /// @param _root The invalid root that was provided
    error Mixer__UnknownRoot(bytes32 _root);
    
    /// @dev Thrown when attempting to reuse a nullifier hash
    /// @param _nullifierHash The nullifier hash that was already used
    error Mixer__NullifierAlreadyUsed(bytes32 _nullifierHash);
    
    /// @dev Thrown when attempting to deposit a commitment that already exists
    /// @param commitment The commitment that was already saved
    error Mixer__CommitmentAlreadySaved(bytes32 commitment);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Initializes the Mixer contract
     * @param _verifier The address of the zero-knowledge proof verifier contract
     * @param _treeDepth The depth of the Merkle tree (determines max capacity)
     * @param _hasher The Poseidon2 hasher contract for Merkle tree operations
     * @dev Inherits from IncrementalMerkleTree and initializes it with the given parameters
     */
    constructor(IVerifier _verifier, uint32 _treeDepth, Poseidon2 _hasher) 
        IncrementalMerkleTree(_treeDepth, _hasher) {
        i_verifier = _verifier;
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Deposits ETH along with a commitment to the mixer
     * @param _commitment The commitment hash (typically hash of secret and nullifier)
     * @dev Requirements:
     *      - Must send exactly DENOMINATION amount of ETH
     *      - Commitment must not have been used before
     *      - Uses reentrancy guard for security
     *      
     *      The commitment is added to the Merkle tree, creating an anonymity set.
     *      Users must remember their secret and nullifier to withdraw later.
     */
    function deposit(bytes32 _commitment) external payable nonReentrant {
        // Check if commitment already exists
        if(s_commitments[_commitment]) {
            revert Mixer__CommitmentAlreadySaved(_commitment);
        }

        // Verify correct deposit amount
        if(msg.value != DENOMINATION) {
            revert Mixer__InvalidEthDeposition(msg.value, DENOMINATION);
        }
        
        // Insert commitment into Merkle tree
        uint32 insertedIndex = _insert(_commitment);
        s_commitments[_commitment] = true;

        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    /**
     * @notice Withdraws ETH from the mixer using a zero-knowledge proof
     * @param proof The zero-knowledge proof (Noir/Plonk format)
     * @param _root The Merkle tree root that includes the user's commitment
     * @param _nullifierHash The nullifier hash to prevent double-spending
     * @param _receiver The address to receive the withdrawn ETH
     * @dev Requirements:
     *      - Root must be a known historical root
     *      - Nullifier must not have been used before
     *      - Zero-knowledge proof must verify correctly
     *      - Uses reentrancy guard for security
     *      
     *      The proof demonstrates:
     *      - User knows a secret and nullifier whose commitment is in the tree
     *      - The nullifier corresponds to the provided nullifier hash
     *      - The user authorizes withdrawal to the specified receiver
     */
    function withdraw(
        bytes memory proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _receiver
    ) external nonReentrant {
        // Verify the root exists in our history
        if(!isKnownRoot(_root)) {
            revert Mixer__UnknownRoot(_root);
        }

        // Prevent nullifier reuse (double-spending)
        if(s_nullifierHashes[_nullifierHash]) {
            revert Mixer__NullifierAlreadyUsed(_nullifierHash);
        }
        
        // Prepare public inputs for proof verification
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = _root;                                    // Merkle root
        publicInputs[1] = _nullifierHash;                          // Nullifier hash
        publicInputs[2] = bytes32(uint256(uint160(address(_receiver)))); // Receiver address

        // Verify the zero-knowledge proof
        if(!i_verifier.verify(proof, publicInputs)) {
            revert Mixer__InvalidProof();
        }

        // Mark nullifier as used
        s_nullifierHashes[_nullifierHash] = true;

        // Transfer ETH to receiver
        (bool success, ) = _receiver.call{value: DENOMINATION}("");
        if(!success) {
            revert Mixer__TransferFailed();
        }

        emit Withdraw(_receiver, _nullifierHash, DENOMINATION);
    }
}
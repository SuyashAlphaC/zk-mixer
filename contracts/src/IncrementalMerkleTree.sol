//SPDX-License-Identifier:MIT

pragma solidity ^0.8.19;
import {Poseidon2, Field} from "@poseidon2/src/Poseidon2.sol";

/** 
 * @title IncrementalMerkleTree
 * @author Suyash Agrawal
 * @notice A Merkle tree implementation that supports incremental insertion of leaves
 * @dev This contract implements an incremental Merkle tree using Poseidon2 hash function.
 *      It maintains a history of roots and uses cached subtrees for efficient insertions.
 *      The tree is optimized for privacy applications like Tornado Cash.
 */
contract IncrementalMerkleTree {
    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Maximum number of historical roots to maintain
    uint32 public constant ROOT_HISTORY_SIZE = 30;

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE VARIABLES
    //////////////////////////////////////////////////////////////*/
    
    /// @notice The depth of the Merkle tree (determines max capacity: 2^depth leaves)
    uint32 public immutable i_depth;
    
    /// @notice The Poseidon2 hasher instance used for computing hashes
    Poseidon2 public immutable i_hasher;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    
    /// @notice The index where the next leaf will be inserted
    uint32 public s_nextLeafIndex;
    
    /// @notice Cached subtree hashes for efficient incremental insertions
    /// @dev Maps tree level to the rightmost subtree hash at that level
    mapping(uint32 => bytes32) s_cachedSubTrees;
    
    /// @notice Historical roots of the Merkle tree
    /// @dev Circular buffer storing the last ROOT_HISTORY_SIZE roots
    mapping(uint256 => bytes32) s_roots;
    
    /// @notice Current index in the roots circular buffer
    uint32 public s_currentRootIndex;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/
    
    /// @dev Thrown when tree depth is zero
    error IncrementalMerkleTree__DepthShouldBeMoreThanZero();
    
    /// @dev Thrown when tree depth is >= 32 (would cause overflow)
    error IncrementalMerkleTree__DepthShouldBeLessThan32();
    
    /// @dev Thrown when requesting zero hash for invalid tree level
    /// @param depth The invalid depth that was requested
    error IncrementalMerkleTree__MerkleTreeIndexOutOfBounds(uint32 depth);
    
    /// @dev Thrown when trying to insert into a full tree
    /// @param currentIndex The current leaf index when tree became full
    error IncrementalMerkleTree__MerkleTreeFull(uint32 currentIndex);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Initializes the Merkle tree with specified depth and hasher
     * @param _depth The depth of the Merkle tree (must be > 0 and < 32)
     * @param _hasher The Poseidon2 hasher contract to use
     * @dev Sets up the initial root as the hash of all zero leaves
     */
    constructor(uint32 _depth, Poseidon2 _hasher) {
        if(_depth <= 0) {
            revert IncrementalMerkleTree__DepthShouldBeMoreThanZero();
        }

        if(_depth >= 32) {
            revert IncrementalMerkleTree__DepthShouldBeLessThan32();
        }

        i_depth = _depth;
        s_roots[0] = zeroes(_depth);
        i_hasher = _hasher;
    }

    /*//////////////////////////////////////////////////////////////
                            PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Inserts a new leaf into the Merkle tree
     * @param _leaf The leaf value to insert
     * @return The index at which the leaf was inserted
     * @dev Updates cached subtrees and computes new root incrementally.
     *      The function traverses up the tree, updating hashes level by level.
     *      For even indices, the leaf becomes the left child; for odd indices, it becomes the right child.
     */
    function _insert(bytes32 _leaf) public returns(uint32) {
        uint32 currentIndex = s_nextLeafIndex; 
        uint32 _nextLeafIndex = s_nextLeafIndex;
        
        // Check if tree is full
        if(currentIndex == uint32(2) ** i_depth) {
            revert IncrementalMerkleTree__MerkleTreeFull(currentIndex);
        }
        
        bytes32 currentHash = _leaf;
        bytes32 left;
        bytes32 right;
        
        // Traverse up the tree, computing hashes level by level
        for(uint32 i = 0 ; i < i_depth ; i ++ ) {
            if(currentIndex % 2 == 0) {
                // Current node is a left child
                left = currentHash;
                right = zeroes(i);  // Use zero hash for missing right sibling
                s_cachedSubTrees[i] = currentHash;  // Cache this subtree
            } else {
                // Current node is a right child
                left = s_cachedSubTrees[i];  // Get cached left sibling
                right = currentHash;
            }

            // Compute parent hash using Poseidon2
            currentHash = Field.toBytes32(i_hasher.hash_2(Field.toField(left), Field.toField(right)));
            
            // Move to parent level
            currentIndex /= 2;
        }
        
        // Update root history (circular buffer)
        uint32 newRootIndex = (s_currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        s_currentRootIndex = newRootIndex;
        s_roots[newRootIndex] = currentHash;
        
        // Increment next leaf index
        s_nextLeafIndex += 1;
        
        return _nextLeafIndex;
    }

    /**
     * @notice Checks if a given root is known (exists in history)
     * @param _root The root hash to check
     * @return True if the root exists in the historical roots, false otherwise
     * @dev Searches through the circular buffer of historical roots.
     *      Returns false for zero hash to prevent attacks.
     */
    function isKnownRoot(bytes32 _root) public view returns(bool) {
        if(_root == bytes32(0)) {
            return false;
        }
        
        uint32 _currentRootIndex = s_currentRootIndex;
        uint32 i = _currentRootIndex;
        
        // Search through circular buffer
        do { 
            if(_root == s_roots[i]) {
                return true;
            }
            if(i == 0) {
                i = ROOT_HISTORY_SIZE;
            }
            i -- ;
        } while (i != s_currentRootIndex);
        
        return false;
    }
    
    /**
     * @notice Returns the zero hash for a given tree level
     * @param i The tree level (0 = leaf level, increases toward root)
     * @return The precomputed zero hash for level i
     * @dev These are precomputed hashes of subtrees containing all zero leaves.
     *      Used to efficiently compute hashes when parts of the tree are empty.
     *      The values are computed as: zeroes[i] = hash(zeroes[i-1], zeroes[i-1])
     */
    function zeroes(uint32 i) public pure returns(bytes32 ) {
        if (i == 0) return bytes32(0x0d823319708ab99ec915efd4f7e03d11ca1790918e8f04cd14100aceca2aa9ff);
        else if (i == 1) return bytes32(0x170a9598425eb05eb8dc06986c6afc717811e874326a79576c02d338bdf14f13);
        else if (i == 2) return bytes32(0x273b1a40397b618dac2fc66ceb71399a3e1a60341e546e053cbfa5995e824caf);
        else if (i == 3) return bytes32(0x16bf9b1fb2dfa9d88cfb1752d6937a1594d257c2053dff3cb971016bfcffe2a1);
        else if (i == 4) return bytes32(0x1288271e1f93a29fa6e748b7468a77a9b8fc3db6b216ce5fc2601fc3e9bd6b36);
        else if (i == 5) return bytes32(0x1d47548adec1068354d163be4ffa348ca89f079b039c9191378584abd79edeca);
        else if (i == 6) return bytes32(0x0b98a89e6827ef697b8fb2e280a2342d61db1eb5efc229f5f4a77fb333b80bef);
        else if (i == 7) return bytes32(0x231555e37e6b206f43fdcd4d660c47442d76aab1ef552aef6db45f3f9cf2e955);
        else if (i == 8) return bytes32(0x03d0dc8c92e2844abcc5fdefe8cb67d93034de0862943990b09c6b8e3fa27a86);
        else if (i == 9) return bytes32(0x1d51ac275f47f10e592b8e690fd3b28a76106893ac3e60cd7b2a3a443f4e8355);
        else if (i == 10) return bytes32(0x16b671eb844a8e4e463e820e26560357edee4ecfdbf5d7b0a28799911505088d);
        else if (i == 11) return bytes32(0x115ea0c2f132c5914d5bb737af6eed04115a3896f0d65e12e761ca560083da15);
        else if (i == 12) return bytes32(0x139a5b42099806c76efb52da0ec1dde06a836bf6f87ef7ab4bac7d00637e28f0);
        else if (i == 13) return bytes32(0x0804853482335a6533eb6a4ddfc215a08026db413d247a7695e807e38debea8e);
        else if (i == 14) return bytes32(0x2f0b264ab5f5630b591af93d93ec2dfed28eef017b251e40905cdf7983689803);
        else if (i == 15) return bytes32(0x170fc161bf1b9610bf196c173bdae82c4adfd93888dc317f5010822a3ba9ebee);
        else if (i == 16) return bytes32(0x0b2e7665b17622cc0243b6fa35110aa7dd0ee3cc9409650172aa786ca5971439);
        else if (i == 17) return bytes32(0x12d5a033cbeff854c5ba0c5628ac4628104be6ab370699a1b2b4209e518b0ac5);
        else if (i == 18) return bytes32(0x1bc59846eb7eafafc85ba9a99a89562763735322e4255b7c1788a8fe8b90bf5d);
        else if (i == 19) return bytes32(0x1b9421fbd79f6972a348a3dd4721781ec25a5d8d27342942ae00aba80a3904d4);
        else if (i == 20) return bytes32(0x087fde1c4c9c27c347f347083139eee8759179d255ec8381c02298d3d6ccd233);
        else if (i == 21) return bytes32(0x1e26b1884cb500b5e6bbfdeedbdca34b961caf3fa9839ea794bfc7f87d10b3f1);
        else if (i == 22) return bytes32(0x09fc1a538b88bda55a53253c62c153e67e8289729afd9b8bfd3f46f5eecd5a72);
        else if (i == 23) return bytes32(0x14cd0edec3423652211db5210475a230ca4771cd1e45315bcd6ea640f14077e2);
        else if (i == 24) return bytes32(0x1d776a76bc76f4305ef0b0b27a58a9565864fe1b9f2a198e8247b3e599e036ca);
        else if (i == 25) return bytes32(0x1f93e3103fed2d3bd056c3ac49b4a0728578be33595959788fa25514cdb5d42f);
        else if (i == 26) return bytes32(0x138b0576ee7346fb3f6cfb632f92ae206395824b9333a183c15470404c977a3b);
        else if (i == 27) return bytes32(0x0745de8522abfcd24bd50875865592f73a190070b4cb3d8976e3dbff8fdb7f3d);
        else if (i == 28) return bytes32(0x2ffb8c798b9dd2645e9187858cb92a86c86dcd1138f5d610c33df2696f5f6860);
        else if (i == 29) return bytes32(0x2612a1395168260c9999287df0e3c3f1b0d8e008e90cd15941e4c2df08a68a5a);
        else if (i == 30) return bytes32(0x10ebedce66a910039c8edb2cd832d6a9857648ccff5e99b5d08009b44b088edf);
        else if (i == 31) return bytes32(0x213fb841f9de06958cf4403477bdbff7c59d6249daabfee147f853db7c808082);
        else revert IncrementalMerkleTree__MerkleTreeIndexOutOfBounds(i);
    }
}

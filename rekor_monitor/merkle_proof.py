"""
Module for handling Merkle proof operations.

Provides classes and functions to verify consistency and inclusion in Merkle trees.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1

class Hasher:
    """
    A hasher class for computing Merkle tree hashes using a specified hash function.
    """
    def __init__(self, hash_func=hashlib.sha256):
        """
        Initializes the Hasher with the given hash function.

        Args:
            hash_func(callable, optional): A hash function from hashlib. Defaults to hashlib.sha256.
        """
        self.hash_func = hash_func

    def new(self):
        """
        Creates a new hash object using the hasher's hash function.

        Returns:
            hash object: A new hash object.
        """
        return self.hash_func()

    def empty_root(self):
        """
        Computes the hash of an empty Merkle tree.

        Returns:
            bytes: The digest of the empty root.
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """
        Hashes a leaf node with the appropriate prefix.

        Args:
            leaf (bytes): The leaf data to hash.

        Returns:
            bytes: The hashed leaf.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """
        Hashes the concatenation of two child hashes with the appropriate prefix.

        Args:
            left (bytes): The left child hash.
            right (bytes): The right child hash.

        Returns:
            bytes: The hashed parent node.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """
        Returns:
            int: The size of the hash digest in bytes.
        """
        return self.new().digest_size

# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)

def verify_consistency(hasher, sizes, proof, roots):
    """
    Verifies the consistency of two Merkle trees of different sizes.

    Args:
        hasher (Hasher): The hasher instance.
        sizes (int tuple): The sizes of the Merkle trees.
        proof (list): The consistency proof hashes as hex strings.
        roots (str tuple): The root hashes of the trees as hex strings.

    Raises:
        ValueError: If the proof is invalid or the sizes are inconsistent.
        RootMismatchError: If the calculated roots do not match the expected roots.
    """
    # change format of args to be bytearray instead of hex strings
    roots = (bytes.fromhex(roots[0]), bytes.fromhex(roots[1]))
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if sizes[1] < sizes[0]:
        raise ValueError(f"size2 ({sizes[1]}) < size1 ({sizes[0]})")
    if sizes[0] == sizes[1]:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(roots[0], roots[1])
        print("Consistency verification succeeded: The trees are consistent.")
        return
    if sizes[0] == 0:
        if bytearray_proof:
            raise ValueError(f"expected empty bytearray_proof,\
                              but got {len(bytearray_proof)} components")
        print("Consistency verification succeeded: The trees are consistent.")
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(sizes[0] - 1, sizes[1])
    shift = (sizes[0] & -sizes[0]).bit_length() - 1
    inner -= shift

    if sizes[0] == 1 << shift:
        seed, start = roots[0], 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(f"wrong bytearray_proof size {len(bytearray_proof)},\
                          want {start + inner + border}")

    bytearray_proof = bytearray_proof[start:]

    mask = (sizes[0] - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, roots[0])

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, roots[1])
    print("Consistency verification succeeded: The trees are consistent.")

def verify_match(calculated, expected):
    """
    Checks if the calculated root matches the expected root.

    Args:
        calculated (bytes): The calculated root hash.
        expected (bytes): The expected root hash.

    Raises:
        RootMismatchError: If the roots do not match.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)

def decomp_incl_proof(index, size):
    """
    Decomposes the inclusion proof into inner and border components.

    Args:
        index (int): The index of the entry.
        size (int): The size of the tree.

    Returns:
        Tuple[int, int]: A tuple containing the number of inner and border hashes.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count('1')
    return inner, border

def inner_proof_size(index, size):
    """
    Calculates the size of the inner proof.

    Args:
        index (int): The index of the entry.
        size (int): The size of the tree.

    Returns:
        int: The inner proof size.
    """
    return (index ^ (size - 1)).bit_length()

def chain_inner(hasher, seed, proof, index):
    """
    Chains the inner proof hashes to compute the root.

    Args:
        hasher (Hasher): The hasher instance.
        seed (bytes): The initial seed hash.
        proof (List[bytes]): List of proof hashes.
        index (int): The index for hash direction.

    Returns:
        bytes: The computed hash.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed

def chain_inner_right(hasher, seed, proof, index):
    """
    Chains the inner right proof hashes to compute the root.

    Args:
        hasher (Hasher): The hasher instance.
        seed (bytes): The initial seed hash.
        proof (List[bytes]): List of proof hashes.
        index (int): The index for hash direction.

    Returns:
        bytes: The computed hash.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed

def chain_border_right(hasher, seed, proof):
    """
    Chains the border right proof hashes to compute the root.

    Args:
        hasher (Hasher): The hasher instance.
        seed (bytes): The initial seed hash.
        proof (List[bytes]): List of proof hashes.

    Returns:
        bytes: The computed hash.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed

class RootMismatchError(Exception):
    """
    Exception raised when calculated root does not match the expected root.

    Attributes:
        expected_root (bytes): The expected root hash.
        calculated_root (bytes): The calculated root hash.
    """
    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return f"calculated root:\n{self.calculated_root}\n \
            does not match expected root:\n{self.expected_root}"

def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Computes the Merkle root from an inclusion proof.

    Args:
        hasher (Hasher): The hasher instance.
        index (int): The index of the leaf.
        size (int): The size of the tree.
        leaf_hash (bytes): The hash of the leaf.
        proof (List[bytes]): The inclusion proof hashes.

    Returns:
        bytes: The computed Merkle root.

    Raises:
        ValueError: If the index is beyond the size or proof size is incorrect.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}")

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, index_size, hashes, proof, debug=False):
    """
    Verifies the inclusion of a leaf in the Merkle tree.

    Args:
        hasher (Hasher): The hasher instance.
        index_size (int tuple): The index of the leaf and the size of the tree.
        hashes (str): The leaf hash and the root hash as hex strings.
        proof (List[str]): The inclusion proof hashes as hex strings.
        debug (bool, optional): If True, prints debugging information.

    Raises:
        RootMismatchError: If the calculated root does not match the expected root.
    """
    index, size = index_size
    leaf_hash, root = hashes

    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(hasher, index, size, bytearray_leaf, bytearray_proof)
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())
    print("Inclusion is valid.")

# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """
    Computes the leaf hash for a given log entry body.

    Args:
        body (str): The base64-encoded body of the log entry.

    Returns:
        str: The computed leaf hash as a hex string.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()

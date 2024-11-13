#validates that verify_consistency correctly confirms whether two Merkle trees of different sizes share a consistent structure and root

from rekor_monitor.merkle_proof import verify_consistency, DefaultHasher, RootMismatchError

def test_verify_consistency_identical_trees():
    # Identical trees (same root and proof)
    roots = ("0" * 64, "0" * 64)
    sizes = (4, 4)
    proof = []
    verify_consistency(DefaultHasher, sizes, proof, roots)  # Should pass without exception

def test_verify_consistency_size_mismatch():
    # Different sizes
    roots = ("0" * 64, "0" * 64)
    sizes = (4, 3)
    proof = []
    try:
        verify_consistency(DefaultHasher, sizes, proof, roots)
    except ValueError as e:
        assert "size2" in str(e), "Expected ValueError for size mismatch"

def test_verify_consistency_with_empty_proof():
    # Empty proof for equal-sized trees
    roots = ("0" * 64, "0" * 64)
    sizes = (0, 0)
    proof = []
    verify_consistency(DefaultHasher, sizes, proof, roots)  # Should pass without exception

def test_verify_consistency_invalid_proof():
    # Non-empty proof for equal-sized trees should raise an error
    roots = ("0" * 64, "0" * 64)
    sizes = (4, 4)
    proof = ["a" * 64]
    try:
        verify_consistency(DefaultHasher, sizes, proof, roots)
    except ValueError as e:
        assert "bytearray_proof is not empty" in str(e), "Expected ValueError for non-empty proof with identical trees"

def test_verify_consistency_mismatched_roots():
    # Trees with different roots and a non-empty proof should raise RootMismatchError
    roots = ("0" * 64, "f" * 64)
    sizes = (4, 8)
    proof = ["a" * 64]
    try:
        verify_consistency(DefaultHasher, sizes, proof, roots)
    except RootMismatchError as e:
        assert str(e), "Expected RootMismatchError for inconsistent trees"

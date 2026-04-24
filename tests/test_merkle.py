"""Tests for the Merkle tree module."""

import os

import pytest

from lecrv.hashing import H, HASH_LEN, TAG_MERKLE_LEAF, TAG_MERKLE_NODE
from lecrv.merkle import build_tree, make_path, root, verify_path, MerklePath


def random_leaf() -> bytes:
    return os.urandom(HASH_LEN)


def random_leaves(D: int) -> list[bytes]:
    return [random_leaf() for _ in range(D)]


def test_build_tree_requires_power_of_two():
    with pytest.raises(ValueError):
        build_tree(random_leaves(3))
    with pytest.raises(ValueError):
        build_tree(random_leaves(5))


def test_build_tree_requires_correct_leaf_size():
    with pytest.raises(ValueError):
        build_tree([b"\x00" * (HASH_LEN - 1)] * 4)


def test_root_is_deterministic():
    leaves = random_leaves(8)
    t1 = build_tree(leaves)
    t2 = build_tree(leaves)
    assert root(t1) == root(t2)


def test_root_changes_when_any_leaf_changes():
    leaves = random_leaves(8)
    t1 = build_tree(leaves)
    leaves[3] = random_leaf()
    t2 = build_tree(leaves)
    assert root(t1) != root(t2)


@pytest.mark.parametrize("D", [1, 2, 4, 8, 16, 32, 64])
def test_path_verifies_for_every_leaf(D):
    """For every leaf in a tree of size D, its path verifies against the root."""
    leaves = random_leaves(D)
    tree = build_tree(leaves)
    r = root(tree)
    for i in range(D):
        path = make_path(tree, i)
        assert verify_path(path, leaves[i], r) is True


def test_verify_rejects_wrong_leaf():
    leaves = random_leaves(8)
    tree = build_tree(leaves)
    path = make_path(tree, 3)
    wrong_leaf = random_leaf()
    assert verify_path(path, wrong_leaf, root(tree)) is False


def test_verify_rejects_wrong_root():
    leaves = random_leaves(8)
    tree = build_tree(leaves)
    path = make_path(tree, 3)
    other_tree = build_tree(random_leaves(8))
    assert verify_path(path, leaves[3], root(other_tree)) is False


def test_verify_rejects_swapped_key_id():
    """A path with the wrong key_id should not verify even with the right leaf."""
    leaves = random_leaves(8)
    tree = build_tree(leaves)
    path = make_path(tree, 3)
    wrong_path = MerklePath(key_id=4, siblings=path.siblings)
    assert verify_path(wrong_path, leaves[3], root(tree)) is False


def test_verify_rejects_tampered_sibling():
    leaves = random_leaves(8)
    tree = build_tree(leaves)
    path = make_path(tree, 3)
    tampered = list(path.siblings)
    tampered[0] = bytes([tampered[0][0] ^ 0x01]) + tampered[0][1:]
    bad = MerklePath(key_id=3, siblings=tampered)
    assert verify_path(bad, leaves[3], root(tree)) is False


def test_leaf_node_domain_separation():
    """A leaf hash of x must differ from an internal-node hash of x.

    This test checks the tagging discipline: even if someone presents a
    32-byte value that happens to match an internal node value, they can
    never pass it off as a leaf, because the leaf tag is different.
    """
    x = os.urandom(HASH_LEN)
    y = os.urandom(HASH_LEN)
    assert H(TAG_MERKLE_LEAF, x) != H(TAG_MERKLE_NODE, x, y)


def test_path_length_matches_tree_depth():
    """For D = 2^d leaves, every path has exactly d siblings."""
    for d in range(0, 7):
        D = 1 << d
        leaves = random_leaves(D)
        tree = build_tree(leaves)
        for i in range(D):
            path = make_path(tree, i)
            assert len(path.siblings) == d


def test_out_of_range_key_id_rejected():
    leaves = random_leaves(4)
    tree = build_tree(leaves)
    with pytest.raises(ValueError):
        make_path(tree, 4)  # only 0..3 are valid
    with pytest.raises(ValueError):
        make_path(tree, -1)
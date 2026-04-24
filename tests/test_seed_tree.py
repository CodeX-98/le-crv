"""Tests for the GGM puncturable seed tree."""

import random

import pytest

from lecrv.hashing import SEC_PARAM
from lecrv.seed_tree import (
    SeedTree,
    SubtreeNode,
    derive_leaf,
    new_tree,
    puncture,
    storage_bytes,
)


def test_new_tree_frontier_is_single_root():
    t = new_tree(d=4)
    assert len(t.frontier) == 1
    assert t.frontier[0].depth == 0
    assert t.frontier[0].index == 0
    assert len(t.frontier[0].seed) == SEC_PARAM
    assert t.punctured == set()


def test_derive_is_deterministic():
    t1 = new_tree(d=3)
    # Force same root across two trees by copying.
    root_seed = t1.frontier[0].seed
    t2 = SeedTree(d=3, frontier=[SubtreeNode(0, 0, root_seed)])
    for i in range(8):
        assert derive_leaf(t1, i) == derive_leaf(t2, i)


def test_every_leaf_derivable_initially():
    for d in range(0, 6):
        t = new_tree(d=d)
        D = 1 << d
        leaves = [derive_leaf(t, i) for i in range(D)]
        assert len(leaves) == D
        for leaf in leaves:
            assert len(leaf) == SEC_PARAM
        # All leaves should be distinct (w.h.p.).
        assert len(set(leaves)) == D


def test_leaves_survive_puncture_of_other_leaves():
    """Puncturing leaf k must not affect derive_leaf for any other leaf."""
    d = 4
    D = 1 << d
    t = new_tree(d=d)
    before = [derive_leaf(t, i) for i in range(D)]

    puncture(t, 5)

    for i in range(D):
        if i == 5:
            with pytest.raises(ValueError):
                derive_leaf(t, i)
        else:
            assert derive_leaf(t, i) == before[i]


def test_multiple_punctures_sequential():
    d = 4
    D = 1 << d
    t = new_tree(d=d)
    expected = [derive_leaf(t, i) for i in range(D)]

    order = [0, 3, 7, 1, 8, 15]
    for k in order:
        puncture(t, k)

    for i in range(D):
        if i in order:
            with pytest.raises(ValueError):
                derive_leaf(t, i)
        else:
            assert derive_leaf(t, i) == expected[i]


def test_puncture_idempotency_rejected():
    t = new_tree(d=3)
    puncture(t, 2)
    with pytest.raises(ValueError):
        puncture(t, 2)


def test_out_of_range_leaf_rejected():
    t = new_tree(d=3)
    with pytest.raises(ValueError):
        derive_leaf(t, 8)
    with pytest.raises(ValueError):
        derive_leaf(t, -1)
    with pytest.raises(ValueError):
        puncture(t, 8)


def test_frontier_grows_at_most_d_per_puncture():
    """Each puncture grows the frontier by at most d nodes.

    Puncturing a leaf at depth d from a covering node at depth k replaces
    that one covering node with up to (d - k) sibling nodes along the path.
    Since k >= 0, the net growth is at most d per puncture.
    """
    d = 8
    t = new_tree(d=d)

    rng = random.Random(42)
    leaves = list(range(1 << d))
    rng.shuffle(leaves)

    prev = len(t.frontier)
    for k in leaves[: (1 << d) // 2]:
        puncture(t, k)
        assert len(t.frontier) - prev <= d
        prev = len(t.frontier)


def test_frontier_size_bounded_by_p_times_d():
    """After p punctures, |frontier| <= p * d.

    This is the correct storage bound for the GGM puncturable PRF.
    For typical workloads where signatures are issued sparsely, the frontier
    remains orders of magnitude smaller than the D pre-computed shares that
    the baseline requires.
    """
    d = 8
    t = new_tree(d=d)

    rng = random.Random(42)
    leaves = list(range(1 << d))
    rng.shuffle(leaves)

    punctures_done = 0
    for k in leaves[: (1 << d) // 2]:
        puncture(t, k)
        punctures_done += 1
        assert len(t.frontier) <= punctures_done * d


def test_frontier_never_exceeds_D_minus_punctured():
    """Trivial upper bound: the frontier can never cover more leaves than exist.

    Each frontier node covers at least one leaf, and together the frontier
    covers exactly the non-punctured leaves. So |frontier| <= D - |punctured|.
    """
    d = 6
    D = 1 << d
    t = new_tree(d=d)

    rng = random.Random(7)
    leaves = list(range(D))
    rng.shuffle(leaves)

    for k in leaves[:30]:
        puncture(t, k)
        assert len(t.frontier) <= D - len(t.punctured)


def test_storage_bytes_tracks_frontier():
    t = new_tree(d=4)
    assert storage_bytes(t) == SEC_PARAM  # single root
    puncture(t, 0)
    assert storage_bytes(t) == len(t.frontier) * SEC_PARAM


def test_full_puncture_empties_frontier():
    d = 3
    D = 1 << d
    t = new_tree(d=d)
    for i in range(D):
        puncture(t, i)
    assert t.frontier == []
    assert t.punctured == set(range(D))
    for i in range(D):
        with pytest.raises(ValueError):
            derive_leaf(t, i)


def test_depth_zero_tree_has_one_leaf():
    """Edge case: d=0 means a single leaf, which is the root seed itself."""
    t = new_tree(d=0)
    leaf = derive_leaf(t, 0)
    assert leaf == t.frontier[0].seed
    puncture(t, 0)
    assert t.frontier == []


def test_forward_security_property():
    """After puncturing leaf k, the seed for leaf k does not appear anywhere
    in the remaining frontier.

    This is the concrete, testable form of forward security: the value we
    used to be able to derive is now absent from the state. An attacker
    who compromises the party's state after puncturing learns nothing that
    lets them recover the old leaf seed (beyond brute-forcing SHA-256).
    """
    d = 4
    t = new_tree(d=d)
    leaf_before = derive_leaf(t, 6)
    puncture(t, 6)

    for node in t.frontier:
        assert node.seed != leaf_before


def test_sequential_puncture_storage_is_logarithmic_in_D():
    """When puncturing one leaf at a time in order, frontier stays small.

    This is the access pattern of the stateful HBS signer: KeyIDs 0, 1, 2, ...
    used in sequence. After puncturing leaves 0..k-1, the frontier describes
    the remaining suffix {k, k+1, ..., D-1} and has size at most d.
    """
    d = 8
    D = 1 << d
    t = new_tree(d=d)

    for k in range(D // 2):
        puncture(t, k)
        assert len(t.frontier) <= d, (
            f"after sequential puncture of {k + 1} leaves, "
            f"frontier size is {len(t.frontier)}, expected <= {d}"
        )
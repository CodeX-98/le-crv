"""Tests for share expansion."""

import os

import pytest

from lecrv.hashing import SEC_PARAM
from lecrv.lamport import NUM_BITS
from lecrv.share_expansion import expand_sk_share


def test_expansion_shape():
    seed = os.urandom(SEC_PARAM)
    share = expand_sk_share(seed)
    assert len(share) == NUM_BITS
    for row in share:
        assert len(row) == 2
        for v in row:
            assert len(v) == SEC_PARAM


def test_expansion_deterministic():
    seed = os.urandom(SEC_PARAM)
    assert expand_sk_share(seed) == expand_sk_share(seed)


def test_different_seeds_give_different_shares():
    s1 = expand_sk_share(os.urandom(SEC_PARAM))
    s2 = expand_sk_share(os.urandom(SEC_PARAM))
    assert s1 != s2


def test_wrong_seed_length_rejected():
    with pytest.raises(ValueError):
        expand_sk_share(b"\x00" * (SEC_PARAM - 1))


def test_slots_are_independent():
    """Different (i, b) slots within one share are distinct (w.h.p.)."""
    seed = os.urandom(SEC_PARAM)
    share = expand_sk_share(seed)
    flat = [share[i][b] for i in range(NUM_BITS) for b in (0, 1)]
    assert len(set(flat)) == len(flat)
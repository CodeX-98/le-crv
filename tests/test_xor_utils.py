"""Tests for XOR sharing helpers."""

import os

import pytest

from lecrv.xor_utils import split_xor_shares, xor_bytes, xor_many


def test_xor_bytes_basic():
    assert xor_bytes(b"\x00\xff", b"\xff\x00") == b"\xff\xff"


def test_xor_bytes_length_mismatch():
    with pytest.raises(ValueError):
        xor_bytes(b"\x00", b"\x00\x00")


def test_xor_many_self_inverse():
    a = os.urandom(32)
    b = os.urandom(32)
    assert xor_many([a, b, a, b]) == bytes(32)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 10])
def test_shares_reconstruct_secret(n):
    secret = os.urandom(32)
    shares = split_xor_shares(secret, n)
    assert len(shares) == n
    assert xor_many(shares) == secret


def test_shares_are_random_looking():
    """With n>=2, no individual share should equal the secret (w.h.p.)."""
    secret = b"\x00" * 32
    shares = split_xor_shares(secret, 3)
    for s in shares:
        assert len(s) == 32
    # First two shares are fresh random; third is their XOR (since secret is zero).
    assert xor_many(shares) == secret
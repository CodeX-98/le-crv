"""XOR helpers for additive secret sharing."""

from __future__ import annotations

import os
from functools import reduce
from operator import xor


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_many(blobs: list[bytes]) -> bytes:
    """XOR a non-empty list of equal-length byte strings."""
    if not blobs:
        raise ValueError("need at least one input")
    return reduce(xor_bytes, blobs)


def split_xor_shares(secret: bytes, n: int, rng=os.urandom) -> list[bytes]:
    """Split `secret` into n additive (XOR) shares.

    The first n-1 shares are uniformly random; the n-th is set so that
    the XOR of all n shares equals `secret`.
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    shares = [rng(len(secret)) for _ in range(n - 1)]
    last = reduce(xor_bytes, shares, secret)  # secret XOR share_0 XOR ... XOR share_{n-2}
    shares.append(last)
    return shares
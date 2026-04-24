"""Tests for the hashing module."""

from lecrv.hashing import (
    H,
    HASH_LEN,
    TAG_LAMPORT_PK,
    TAG_MERKLE_LEAF,
    hash_message,
)


def test_hash_length():
    """Every hash output is exactly HASH_LEN bytes."""
    out = H(TAG_LAMPORT_PK, b"anything")
    assert len(out) == HASH_LEN


def test_hash_is_deterministic():
    """Same inputs produce the same output."""
    a = H(TAG_LAMPORT_PK, b"abc", b"def")
    b = H(TAG_LAMPORT_PK, b"abc", b"def")
    assert a == b


def test_domain_separation():
    """Different tags on the same payload produce different digests.

    This is the whole point of domain separation: a Lamport-PK hash of X
    must not collide with a Merkle-leaf hash of X.
    """
    x = b"some payload"
    assert H(TAG_LAMPORT_PK, x) != H(TAG_MERKLE_LEAF, x)


def test_concatenation_is_unambiguous():
    """H(tag, 'ab', 'c') and H(tag, 'a', 'bc') are both just tag||abc.

    This test documents a known subtlety: our H function treats its parts
    as a single concatenated stream. That is fine as long as callers always
    pass fixed-length inputs (which every Lamport/Merkle/GGM caller does),
    but it would be unsafe for variable-length inputs without length framing.
    """
    a = H(TAG_LAMPORT_PK, b"ab", b"c")
    b = H(TAG_LAMPORT_PK, b"a", b"bc")
    assert a == b  # Intentional: documents that we rely on fixed-width inputs


def test_hash_message_different_from_raw_hash():
    """hash_message uses the message tag, not any other tag."""
    msg = b"hello world"
    assert hash_message(msg) != H(TAG_LAMPORT_PK, msg)
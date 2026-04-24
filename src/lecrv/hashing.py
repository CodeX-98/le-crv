"""Hashing primitives for LE-CRV.

All hash calls in the library route through this module. I've used SHA-256
throughout. Domain separation is handled by prefixing inputs with a
single-byte tag, which keeps different uses of the hash function
cryptographically independent.
"""

from __future__ import annotations

from Crypto.Hash import SHA256

HASH_LEN = 32  # SHA-256 output length in bytes
SEC_PARAM = 32  # security parameter n, in bytes (matches HASH_LEN)


# Domain separation tags. One byte each. Keep these globally unique.
TAG_LAMPORT_PK = b"\x01"   # hashing a Lamport secret to derive its public value
TAG_MERKLE_LEAF = b"\x02"  # hashing a Lamport PK bundle into a Merkle leaf
TAG_MERKLE_NODE = b"\x03"  # hashing two Merkle children into a parent
TAG_MSG_HASH = b"\x04"     # hashing a message before signing
TAG_PRG_LEFT = b"\x05"     # GGM tree: left child expansion
TAG_PRG_RIGHT = b"\x06"    # GGM tree: right child expansion


def H(tag: bytes, *parts: bytes) -> bytes:
    """Domain-separated SHA-256.

    Concatenates tag || part1 || part2 || ... and returns the 32-byte digest.
    Using a tag prevents an attacker from ever producing the same hash output
    from two different contexts (e.g. a Merkle node vs a Lamport PK derivation).
    """
    h = SHA256.new()
    h.update(tag)
    for p in parts:
        h.update(p)
    return h.digest()


def hash_message(msg: bytes) -> bytes:
    """Hash an arbitrary-length message to a 256-bit digest for signing."""
    return H(TAG_MSG_HASH, msg)
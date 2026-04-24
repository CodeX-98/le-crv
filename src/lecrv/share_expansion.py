"""Deterministic expansion of a party's per-KeyID seed into a full SK share.

Given a 32-byte leaf seed, we need to produce 2 * NUM_BITS = 512 byte strings
of 32 bytes each (one for each (bit_position, bit_value) slot of a Lamport
secret key). We do this via SHA-256 with unique indexing tags.
"""

from __future__ import annotations

from lecrv.hashing import H, SEC_PARAM
from lecrv.lamport import NUM_BITS

# Tag for this expansion. Kept local to this module.
_TAG_SK_EXPAND = b"\x07"


def expand_sk_share(leaf_seed: bytes) -> list[list[bytes]]:
    """Expand a 32-byte seed into a Lamport SK-shaped share.

    Output has shape [NUM_BITS][2], each entry is SEC_PARAM bytes.
    """
    if len(leaf_seed) != SEC_PARAM:
        raise ValueError(f"leaf_seed must be {SEC_PARAM} bytes")

    share: list[list[bytes]] = [[b"", b""] for _ in range(NUM_BITS)]
    for i in range(NUM_BITS):
        for b in (0, 1):
            share[i][b] = H(
                _TAG_SK_EXPAND,
                leaf_seed,
                i.to_bytes(2, "big"),
                bytes([b]),
            )
    return share
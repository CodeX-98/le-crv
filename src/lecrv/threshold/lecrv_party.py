"""LE-CRV signing party.

Holds a puncturable seed tree. For each signing request:
  1. Derive the leaf seed for the requested KeyID.
  2. Expand into a full Lamport-SK-shaped share.
  3. Emit the signature share (one byte string per bit position).
  4. Puncture the leaf so it can never be re-derived.
"""

from __future__ import annotations

from dataclasses import dataclass

from lecrv import seed_tree
from lecrv.hashing import hash_message
from lecrv.lamport import NUM_BITS
from lecrv.share_expansion import expand_sk_share
from lecrv.threshold.lecrv_dealer import LecrvPartyBundle


def _digest_bits(msg: bytes) -> list[int]:
    """MSB-first bit decomposition of hash(msg). Must match lamport._digest_bits."""
    d = hash_message(msg)
    bits: list[int] = []
    for byte in d:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


@dataclass
class LecrvParty:
    """Stateful LE-CRV signing party.

    Forward security: after sign_share(key_id, ...) completes, this party
    has no way to re-derive the share for key_id. Even full state
    compromise at time t reveals nothing about shares used before t.
    """
    bundle: LecrvPartyBundle

    @property
    def party_id(self) -> int:
        return self.bundle.party_id

    @property
    def tree(self):
        return self.bundle.tree

    def sign_share(self, key_id: int, msg: bytes) -> list[bytes]:
        """Produce this party's signature share and puncture the leaf.

        Raises ValueError if the KeyID has already been used (puncture would
        fail) or is out of range.
        """
        # derive_leaf checks range and puncture status; raises on either.
        leaf_seed = seed_tree.derive_leaf(self.tree, key_id)
        sk_share = expand_sk_share(leaf_seed)

        bits = _digest_bits(msg)
        share = [sk_share[i][bits[i]] for i in range(NUM_BITS)]

        # Puncture AFTER successful share computation. If anything above
        # raises, the tree is left intact and the party can retry.
        seed_tree.puncture(self.tree, key_id)

        return share
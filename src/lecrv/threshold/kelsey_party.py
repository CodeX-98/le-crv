"""Kelsey-style signing party: one PRF key, shares derived on the fly.

No puncturing. A `used` set prevents trivial key reuse, but compromise of
the PRF key at any time reveals all shares -- this is the forward-security
gap that LE-CRV closes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lecrv.hashing import hash_message
from lecrv.lamport import NUM_BITS
from lecrv.threshold.kelsey_dealer import KelseyPartyBundle, derive_party_sk_share


def _digest_bits(msg: bytes) -> list[int]:
    d = hash_message(msg)
    bits: list[int] = []
    for byte in d:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


@dataclass
class KelseyParty:
    bundle: KelseyPartyBundle
    used: set[int] = field(default_factory=set)

    @property
    def party_id(self) -> int:
        return self.bundle.party_id

    def sign_share(self, key_id: int, msg: bytes) -> list[bytes]:
        if key_id in self.used:
            raise ValueError(f"party {self.party_id}: KeyID {key_id} already used")
        sk_share = derive_party_sk_share(self.bundle.prf_key, key_id)
        bits = _digest_bits(msg)
        share = [sk_share[i][bits[i]] for i in range(NUM_BITS)]
        self.used.add(key_id)
        return share
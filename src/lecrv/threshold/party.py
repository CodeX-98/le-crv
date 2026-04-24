"""Signing party: holds shares, produces signature shares on request."""

from __future__ import annotations

from dataclasses import dataclass, field

from lecrv.hashing import hash_message
from lecrv.lamport import NUM_BITS
from lecrv.threshold.dealer import PartyShareBundle


def _digest_bits(msg: bytes) -> list[int]:
    """Same bit ordering as lamport._digest_bits (MSB first per byte)."""
    d = hash_message(msg)
    bits: list[int] = []
    for byte in d:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


@dataclass
class Party:
    """Stateful signing party.

    Holds its share bundle and a set of KeyIDs it has already contributed to.
    Refuses to sign twice under the same KeyID. This per-party state check
    is the threshold scheme's defense against one-time-key reuse: forging a
    reuse requires EVERY party to fail in the same way simultaneously.
    """
    bundle: PartyShareBundle
    used: set[int] = field(default_factory=set)

    @property
    def party_id(self) -> int:
        return self.bundle.party_id

    def sign_share(self, key_id: int, msg: bytes) -> list[bytes]:
        """Return this party's XOR share of the Lamport signature on msg.

        For each bit b_i of hash(msg), emit sk_share[key_id][i][b_i].
        """
        if key_id in self.used:
            raise ValueError(
                f"party {self.party_id}: KeyID {key_id} already used"
            )
        if not (0 <= key_id < len(self.bundle.sk_shares)):
            raise ValueError(f"key_id {key_id} out of range")

        bits = _digest_bits(msg)
        share = [
            self.bundle.sk_shares[key_id][i][bits[i]] for i in range(NUM_BITS)
        ]
        self.used.add(key_id)
        return share
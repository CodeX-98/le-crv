"""Kelsey-style aggregator: same combine logic as LE-CRV."""

from __future__ import annotations

from dataclasses import dataclass

from lecrv import merkle
from lecrv.hashing import hash_message
from lecrv.lamport import NUM_BITS
from lecrv.stateful_lamport import Signature
from lecrv.threshold.kelsey_dealer import KelseyPublic
from lecrv.threshold.kelsey_party import KelseyParty
from lecrv.xor_utils import xor_many


@dataclass
class KelseyAggregator:
    public: KelseyPublic

    def sign(self, parties: list[KelseyParty], key_id: int, msg: bytes) -> Signature:
        if len(parties) != self.public.n:
            raise ValueError(f"expected {self.public.n} parties, got {len(parties)}")
        if not (0 <= key_id < self.public.D):
            raise ValueError(f"key_id {key_id} out of range")

        shares = [p.sign_share(key_id, msg) for p in parties]

        digest = hash_message(msg)
        bits = []
        for byte in digest:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)

        corr = self.public.crv.correction
        lamport_sig: list[bytes] = []
        for i in range(NUM_BITS):
            xs = xor_many([shares[p][i] for p in range(self.public.n)])
            lamport_sig.append(
                bytes(x ^ y for x, y in zip(xs, corr[key_id][i][bits[i]]))
            )

        path = merkle.make_path(self.public.tree, key_id)
        return Signature(key_id=key_id, lamport_sig=lamport_sig, path=path)
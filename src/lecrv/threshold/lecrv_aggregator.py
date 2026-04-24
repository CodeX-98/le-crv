"""LE-CRV aggregator: combines party shares with the public correction."""

from __future__ import annotations

from dataclasses import dataclass

from lecrv import merkle
from lecrv.lamport import NUM_BITS
from lecrv.stateful_lamport import Signature
from lecrv.threshold.lecrv_dealer import LecrvPublic
from lecrv.threshold.lecrv_party import LecrvParty
from lecrv.xor_utils import xor_many


@dataclass
class LecrvAggregator:
    """Coordinates n LE-CRV parties; XORs shares with CRV to get final sig."""
    public: LecrvPublic

    def sign(
        self,
        parties: list[LecrvParty],
        key_id: int,
        msg: bytes,
    ) -> Signature:
        if len(parties) != self.public.n:
            raise ValueError(
                f"expected {self.public.n} parties, got {len(parties)}"
            )
        if not (0 <= key_id < self.public.D):
            raise ValueError(f"key_id {key_id} out of range")

        # Collect shares from every party. Each share is list of NUM_BITS
        # byte strings, selected by the message-hash bits.
        shares = [p.sign_share(key_id, msg) for p in parties]

        # Determine which bit was selected at each position so we can look up
        # the matching correction entry. We recompute the bits here rather
        # than having parties report them, because the bits are a public
        # function of the message.
        from lecrv.hashing import hash_message
        digest = hash_message(msg)
        bits = []
        for byte in digest:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)

        # Combine: for each bit position i with selected bit b_i, the true
        # Lamport signature slot is XOR_p(shares[p][i]) XOR correction[key_id][i][b_i].
        corr = self.public.crv.correction
        lamport_sig: list[bytes] = []
        for i in range(NUM_BITS):
            xor_of_shares = xor_many([shares[p][i] for p in range(self.public.n)])
            lamport_sig.append(
                bytes(x ^ y for x, y in zip(xor_of_shares, corr[key_id][i][bits[i]]))
            )

        path = merkle.make_path(self.public.tree, key_id)
        return Signature(key_id=key_id, lamport_sig=lamport_sig, path=path)
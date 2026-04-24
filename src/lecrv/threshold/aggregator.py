"""Untrusted aggregator: coordinates the parties and combines shares."""

from __future__ import annotations

from dataclasses import dataclass

from lecrv import merkle
from lecrv.lamport import NUM_BITS
from lecrv.stateful_lamport import Signature
from lecrv.threshold.dealer import PublicMaterial
from lecrv.threshold.party import Party
from lecrv.xor_utils import xor_many


@dataclass
class Aggregator:
    """Coordinates n parties to produce a single composite signature.

    Holds only public material. Has no signing power of its own.
    """
    public: PublicMaterial

    def sign(
        self,
        parties: list[Party],
        key_id: int,
        msg: bytes,
    ) -> Signature:
        """Ask every party for its share; XOR-combine into a full signature.

        Raises if the party set is the wrong size or any party refuses.
        """
        if len(parties) != self.public.n:
            raise ValueError(
                f"expected {self.public.n} parties, got {len(parties)}"
            )

        # Collect shares from every party.
        shares: list[list[bytes]] = []
        for p in parties:
            shares.append(p.sign_share(key_id, msg))

        # XOR-combine per bit position.
        lamport_sig: list[bytes] = []
        for i in range(NUM_BITS):
            slot_shares = [shares[p_idx][i] for p_idx in range(self.public.n)]
            lamport_sig.append(xor_many(slot_shares))

        path = merkle.make_path(self.public.tree, key_id)
        return Signature(key_id=key_id, lamport_sig=lamport_sig, path=path)
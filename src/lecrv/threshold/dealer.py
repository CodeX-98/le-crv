"""Trusted dealer for the baseline threshold scheme.

Generates a composite Lamport keypair (D one-time keys under a Merkle root),
XOR-splits every secret-key value across n parties, and hands each party a
bundle of shares it will use during signing. The dealer then deletes all
plaintext secret material; only the shares persist.
"""

from __future__ import annotations

from dataclasses import dataclass

from lecrv import lamport, merkle, stateful_lamport
from lecrv.lamport import NUM_BITS
from lecrv.xor_utils import split_xor_shares


@dataclass(frozen=True)
class PartyShareBundle:
    """One party's complete share of the composite signing key.

    party_id:  0-indexed identifier in {0, ..., n-1}
    sk_shares: sk_shares[key_id][i][b] is this party's XOR share of sk[i][b]
               for the one-time key at key_id.
    """
    party_id: int
    sk_shares: list[list[list[bytes]]]


@dataclass(frozen=True)
class PublicMaterial:
    """Everything the aggregator and verifier need.

    public_root:   Merkle root; the canonical public key.
    one_time_pks:  the D Lamport public keys (for verifier convenience in this
                   baseline; a real wire format would carry the relevant PK
                   inside each signature).
    tree:          full Merkle tree (for aggregator path generation).
    D:             number of one-time keys.
    n:             number of parties.
    """
    public_root: bytes
    one_time_pks: list[list[list[bytes]]]
    tree: list[bytes]
    D: int
    n: int


def deal(D: int, n: int) -> tuple[PublicMaterial, list[PartyShareBundle]]:
    """Run the trusted setup.

    Returns (public_material, [bundle_for_party_0, ..., bundle_for_party_{n-1}]).
    The dealer forgets all plaintext SKs after this function returns.
    """
    if n < 1:
        raise ValueError("n must be >= 1")

    ck = stateful_lamport.keygen(D)

    # For each party, build an empty shares[key_id][i][b] structure.
    per_party_shares: list[list[list[list[bytes]]]] = [
        [[[b"" for _ in range(2)] for _ in range(NUM_BITS)] for _ in range(D)]
        for _ in range(n)
    ]

    # Split every SK byte string into n XOR shares.
    for key_id in range(D):
        sk = ck.keypairs[key_id].sk
        for i in range(NUM_BITS):
            for b in (0, 1):
                shares = split_xor_shares(sk[i][b], n)
                for party_id in range(n):
                    per_party_shares[party_id][key_id][i][b] = shares[party_id]

    bundles = [
        PartyShareBundle(party_id=p, sk_shares=per_party_shares[p])
        for p in range(n)
    ]

    public_material = PublicMaterial(
        public_root=ck.public_root,
        one_time_pks=[kp.pk for kp in ck.keypairs],
        tree=ck.tree,
        D=D,
        n=n,
    )

    # Dealer forgets plaintext SKs by simply not returning them.
    return public_material, bundles
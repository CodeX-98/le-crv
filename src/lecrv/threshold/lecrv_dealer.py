"""LE-CRV dealer: distributes seed trees plus a public correction value.

Instead of giving each party D full Lamport-SK shares (the baseline), we give
each party:
  - one seed tree of depth d = log2(D)

From this seed tree, the party can derive its share for any KeyID on demand,
and puncture it once used.

Additionally, the dealer publishes (per KeyID) a correction value such that
the XOR of all parties' derived shares, XORed with the correction, equals the
true Lamport secret. The correction values form the common reference value
(CRV) in the Kelsey et al. sense.
"""

from __future__ import annotations

from dataclasses import dataclass

from lecrv import lamport, merkle, seed_tree, stateful_lamport
from lecrv.lamport import NUM_BITS
from lecrv.share_expansion import expand_sk_share
from lecrv.seed_tree import SeedTree
from lecrv.xor_utils import xor_bytes


@dataclass
class LecrvPartyBundle:
    """One party's LE-CRV share bundle.

    party_id:   0-indexed identifier in {0, ..., n-1}
    tree:       puncturable seed tree of depth d = log2(D)
    """
    party_id: int
    tree: SeedTree


@dataclass(frozen=True)
class CommonReferenceValue:
    """Public correction values, indexed by KeyID.

    correction[key_id][i][b] is the XOR of the true sk[key_id][i][b] with the
    sum of all parties' derived shares for that slot. Aggregator XORs this
    into the combined shares to recover the real signature.
    """
    correction: list[list[list[bytes]]]


@dataclass(frozen=True)
class LecrvPublic:
    """Everything public after the dealer finishes.

    public_root:   Merkle root; the canonical public key
    one_time_pks:  D Lamport public keys (aggregator/verifier convenience)
    tree:          full Merkle tree for path generation
    crv:           common reference values (the correction table)
    D:             number of one-time keys
    n:             number of parties
    d:             log2(D)
    """
    public_root: bytes
    one_time_pks: list[list[list[bytes]]]
    tree: list[bytes]
    crv: CommonReferenceValue
    D: int
    n: int
    d: int


def deal(D: int, n: int) -> tuple[LecrvPublic, list[LecrvPartyBundle]]:
    """Run the LE-CRV trusted setup.

    Returns (public_material, [bundle_for_party_0, ..., bundle_for_party_{n-1}]).
    The dealer forgets all plaintext SKs and all party seed-tree roots after
    this function returns (by virtue of not holding references to them).
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    if D < 1 or (D & (D - 1)) != 0:
        raise ValueError(f"D must be a power of two, got {D}")

    d = D.bit_length() - 1

    # 1. Generate the composite key (D Lamport keypairs + Merkle tree).
    ck = stateful_lamport.keygen(D)

    # 2. Give each party a fresh seed tree of depth d.
    party_trees = [seed_tree.new_tree(d=d) for _ in range(n)]

    # 3. For each KeyID, compute the correction so that
    #       XOR_p(share_p) XOR correction = true_sk
    #    i.e. correction = true_sk XOR XOR_p(share_p).
    correction: list[list[list[bytes]]] = [
        [[b"", b""] for _ in range(NUM_BITS)] for _ in range(D)
    ]

    for key_id in range(D):
        true_sk = ck.keypairs[key_id].sk  # shape [NUM_BITS][2]

        # Derive each party's share for this KeyID without mutating the tree.
        per_party_share: list[list[list[bytes]]] = []
        for p in range(n):
            leaf_seed = seed_tree.derive_leaf(party_trees[p], key_id)
            per_party_share.append(expand_sk_share(leaf_seed))

        # XOR-sum across parties, per (i, b) slot.
        for i in range(NUM_BITS):
            for b in (0, 1):
                xor_sum = per_party_share[0][i][b]
                for p in range(1, n):
                    xor_sum = xor_bytes(xor_sum, per_party_share[p][i][b])
                correction[key_id][i][b] = xor_bytes(true_sk[i][b], xor_sum)

    bundles = [
        LecrvPartyBundle(party_id=p, tree=party_trees[p]) for p in range(n)
    ]

    public = LecrvPublic(
        public_root=ck.public_root,
        one_time_pks=[kp.pk for kp in ck.keypairs],
        tree=ck.tree,
        crv=CommonReferenceValue(correction=correction),
        D=D,
        n=n,
        d=d,
    )

    return public, bundles
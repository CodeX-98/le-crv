"""Kelsey-Lang-Lucks 2025-style dealer (PRF-derived shares, no forward security).(it is the given base paper)

Faithful to §3.4 of Kelsey-Lang-Lucks: each party holds a single PRF key K[t]
and derives its share for any KeyID on the fly via PRF(K[t], KeyID, i, b).
The dealer publishes a correction table (CRV) so that XOR of all derived
shares, XORed with the correction, equals the true Lamport secret.

Difference from LE-CRV: the party's state is a single 32-byte key and never
changes. Compromise of a party at any time t reveals its share for every
KeyID, past and future -- no forward security.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from lecrv import stateful_lamport
from lecrv.hashing import H, SEC_PARAM
from lecrv.lamport import NUM_BITS
from lecrv.xor_utils import xor_bytes


_TAG_KELSEY_PRF = b"\x08"


def kelsey_prf(key: bytes, key_id: int, i: int, b: int) -> bytes:
    """Keyed pseudorandom function, SHA-256 based.

    Returns the SEC_PARAM-byte share value for (key_id, i, b) under `key`.
    """
    return H(
        _TAG_KELSEY_PRF,
        key,
        key_id.to_bytes(4, "big"),
        i.to_bytes(2, "big"),
        bytes([b]),
    )


def derive_party_sk_share(key: bytes, key_id: int) -> list[list[bytes]]:
    """Derive a full Lamport-shaped SK share for one KeyID."""
    share: list[list[bytes]] = [[b"", b""] for _ in range(NUM_BITS)]
    for i in range(NUM_BITS):
        for b in (0, 1):
            share[i][b] = kelsey_prf(key, key_id, i, b)
    return share


@dataclass(frozen=True)
class KelseyPartyBundle:
    party_id: int
    prf_key: bytes  # exactly SEC_PARAM bytes; the ONLY per-party state


@dataclass(frozen=True)
class KelseyCRV:
    correction: list[list[list[bytes]]]  # [key_id][i][b]


@dataclass(frozen=True)
class KelseyPublic:
    public_root: bytes
    one_time_pks: list[list[list[bytes]]]
    tree: list[bytes]
    crv: KelseyCRV
    D: int
    n: int


def deal(D: int, n: int, rng=os.urandom) -> tuple[KelseyPublic, list[KelseyPartyBundle]]:
    if n < 1:
        raise ValueError("n must be >= 1")
    if D < 1 or (D & (D - 1)) != 0:
        raise ValueError(f"D must be a power of two, got {D}")

    ck = stateful_lamport.keygen(D)
    prf_keys = [rng(SEC_PARAM) for _ in range(n)]

    correction: list[list[list[bytes]]] = [
        [[b"", b""] for _ in range(NUM_BITS)] for _ in range(D)
    ]
    for key_id in range(D):
        true_sk = ck.keypairs[key_id].sk
        per_party = [derive_party_sk_share(prf_keys[p], key_id) for p in range(n)]
        for i in range(NUM_BITS):
            for b in (0, 1):
                xs = per_party[0][i][b]
                for p in range(1, n):
                    xs = xor_bytes(xs, per_party[p][i][b])
                correction[key_id][i][b] = xor_bytes(true_sk[i][b], xs)

    bundles = [KelseyPartyBundle(party_id=p, prf_key=prf_keys[p]) for p in range(n)]
    public = KelseyPublic(
        public_root=ck.public_root,
        one_time_pks=[kp.pk for kp in ck.keypairs],
        tree=ck.tree,
        crv=KelseyCRV(correction=correction),
        D=D,
        n=n,
    )
    return public, bundles
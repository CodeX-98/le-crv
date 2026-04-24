"""Tests for the Kelsey-Lang-Lucks-style scheme."""

import pytest

from lecrv.lamport import NUM_BITS
from lecrv.stateful_lamport import verify_with_pk
from lecrv.threshold import KelseyAggregator, KelseyParty, kelsey_deal


def make_parties(bundles):
    return [KelseyParty(bundle=b) for b in bundles]


@pytest.mark.parametrize("D, n", [(2, 2), (4, 3), (8, 5), (16, 4)])
def test_kelsey_sign_verify_roundtrip(D, n):
    public, bundles = kelsey_deal(D=D, n=n)
    parties = make_parties(bundles)
    agg = KelseyAggregator(public=public)
    sig = agg.sign(parties, key_id=0, msg=b"hi")
    pk = public.one_time_pks[0]
    assert verify_with_pk(public.public_root, b"hi", sig, pk)


def test_party_state_is_single_prf_key():
    """Kelsey party storage is exactly one PRF key -- the whole point."""
    _, bundles = kelsey_deal(D=64, n=3)
    assert len(bundles[0].prf_key) == 32
    # No other per-KeyID state.


def test_all_keyids_usable():
    D, n = 8, 3
    public, bundles = kelsey_deal(D=D, n=n)
    parties = make_parties(bundles)
    agg = KelseyAggregator(public=public)
    for key_id in range(D):
        sig = agg.sign(parties, key_id=key_id, msg=f"m{key_id}".encode())
        pk = public.one_time_pks[key_id]
        assert verify_with_pk(public.public_root, f"m{key_id}".encode(), sig, pk)


def test_key_reuse_rejected():
    public, bundles = kelsey_deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = KelseyAggregator(public=public)
    agg.sign(parties, key_id=1, msg=b"first")
    with pytest.raises(ValueError):
        agg.sign(parties, key_id=1, msg=b"second")


def test_no_forward_security():
    """After signing with KeyID k, the party's PRF key still derives share
    for KeyID k (and every other KeyID). This documents the gap LE-CRV closes.
    """
    from lecrv.threshold.kelsey_dealer import derive_party_sk_share

    public, bundles = kelsey_deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = KelseyAggregator(public=public)

    # Sign with KeyID 1.
    agg.sign(parties, key_id=1, msg=b"first")

    # The PRF key has not changed; an attacker with post-signing state
    # can still derive the share for KeyID 1.
    p0 = parties[0]
    share_after = derive_party_sk_share(p0.bundle.prf_key, 1)
    assert len(share_after) == NUM_BITS
    # (The derivation succeeds -- that's the lack of forward security.)
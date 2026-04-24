"""Tests for the baseline threshold layer."""

import pytest

from lecrv.lamport import NUM_BITS
from lecrv.stateful_lamport import verify_with_pk
from lecrv.threshold import Aggregator, Party, deal


def make_parties(bundles):
    return [Party(bundle=b) for b in bundles]


@pytest.mark.parametrize("D, n", [(2, 2), (4, 3), (8, 5), (16, 4)])
def test_threshold_sign_verify_roundtrip(D, n):
    public, bundles = deal(D=D, n=n)
    parties = make_parties(bundles)
    agg = Aggregator(public=public)

    msg = b"threshold hello"
    sig = agg.sign(parties, key_id=0, msg=msg)

    pk = public.one_time_pks[sig.key_id]
    assert verify_with_pk(public.public_root, msg, sig, pk) is True


def test_signature_identical_in_shape_to_single_signer():
    """Threshold signature has the same field shape as a non-threshold one."""
    public, bundles = deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = Aggregator(public=public)

    sig = agg.sign(parties, key_id=0, msg=b"x")
    assert sig.key_id == 0
    assert len(sig.lamport_sig) == NUM_BITS
    assert all(len(slot) == 32 for slot in sig.lamport_sig)


def test_missing_party_fails():
    public, bundles = deal(D=4, n=4)
    parties = make_parties(bundles)[:-1]  # drop one
    agg = Aggregator(public=public)

    with pytest.raises(ValueError):
        agg.sign(parties, key_id=0, msg=b"x")


def test_party_refuses_key_reuse():
    public, bundles = deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = Aggregator(public=public)

    agg.sign(parties, key_id=1, msg=b"first")
    with pytest.raises(ValueError):
        agg.sign(parties, key_id=1, msg=b"second")


def test_different_keyids_independent():
    public, bundles = deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = Aggregator(public=public)

    s0 = agg.sign(parties, key_id=0, msg=b"m0")
    s2 = agg.sign(parties, key_id=2, msg=b"m2")

    pk0 = public.one_time_pks[0]
    pk2 = public.one_time_pks[2]
    assert verify_with_pk(public.public_root, b"m0", s0, pk0)
    assert verify_with_pk(public.public_root, b"m2", s2, pk2)


def test_subset_of_parties_cannot_forge():
    """XOR-combining n-1 shares yields garbage, not a valid signature.

    Check that if only n-1 parties contribute, the resulting (incorrectly
    combined) signature does not verify. This is the essential n-of-n
    security property.
    """
    public, bundles = deal(D=2, n=4)
    parties = make_parties(bundles)
    msg = b"attempt forgery"

    # Manually XOR only the first n-1 shares.
    from lecrv.threshold.party import _digest_bits
    from lecrv.xor_utils import xor_many
    from lecrv.stateful_lamport import Signature
    from lecrv import merkle

    shares = [p.sign_share(0, msg) for p in parties[:-1]]
    fake_sig = [
        xor_many([shares[p][i] for p in range(len(shares))])
        for i in range(NUM_BITS)
    ]
    path = merkle.make_path(public.tree, 0)
    bad = Signature(key_id=0, lamport_sig=fake_sig, path=path)

    pk = public.one_time_pks[0]
    assert verify_with_pk(public.public_root, msg, bad, pk) is False


def test_verify_rejects_wrong_pk():
    public, bundles = deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = Aggregator(public=public)

    sig = agg.sign(parties, key_id=1, msg=b"m")
    wrong_pk = public.one_time_pks[2]
    assert verify_with_pk(public.public_root, b"m", sig, wrong_pk) is False


def test_all_keyids_usable_with_threshold():
    D, n = 8, 3
    public, bundles = deal(D=D, n=n)
    parties = make_parties(bundles)
    agg = Aggregator(public=public)

    for key_id in range(D):
        sig = agg.sign(parties, key_id=key_id, msg=f"m{key_id}".encode())
        pk = public.one_time_pks[key_id]
        assert verify_with_pk(
            public.public_root, f"m{key_id}".encode(), sig, pk
        )
"""Tests for the LE-CRV (seed-tree-based) threshold scheme."""

import pytest

from lecrv.lamport import NUM_BITS
from lecrv.stateful_lamport import verify_with_pk
from lecrv.threshold import LecrvAggregator, LecrvParty, lecrv_deal


def make_parties(bundles):
    return [LecrvParty(bundle=b) for b in bundles]


@pytest.mark.parametrize("D, n", [(2, 2), (4, 3), (8, 5), (16, 4)])
def test_lecrv_sign_verify_roundtrip(D, n):
    public, bundles = lecrv_deal(D=D, n=n)
    parties = make_parties(bundles)
    agg = LecrvAggregator(public=public)

    msg = b"le-crv hello"
    sig = agg.sign(parties, key_id=0, msg=msg)

    pk = public.one_time_pks[sig.key_id]
    assert verify_with_pk(public.public_root, msg, sig, pk) is True


def test_signature_shape_matches_single_signer():
    public, bundles = lecrv_deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = LecrvAggregator(public=public)
    sig = agg.sign(parties, key_id=2, msg=b"x")
    assert sig.key_id == 2
    assert len(sig.lamport_sig) == NUM_BITS
    assert all(len(slot) == 32 for slot in sig.lamport_sig)


def test_all_keyids_usable():
    D, n = 8, 3
    public, bundles = lecrv_deal(D=D, n=n)
    parties = make_parties(bundles)
    agg = LecrvAggregator(public=public)

    for key_id in range(D):
        sig = agg.sign(parties, key_id=key_id, msg=f"m{key_id}".encode())
        pk = public.one_time_pks[key_id]
        assert verify_with_pk(
            public.public_root, f"m{key_id}".encode(), sig, pk
        )


def test_key_reuse_rejected():
    public, bundles = lecrv_deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = LecrvAggregator(public=public)

    agg.sign(parties, key_id=1, msg=b"first")
    with pytest.raises(ValueError):
        agg.sign(parties, key_id=1, msg=b"second")


def test_forward_security_single_party_compromise():
    """After party p signs with KeyID k, inspecting p's state reveals nothing
    that lets anyone reconstruct p's share for KeyID k.

    We verify this operationally: after the signing operation, the party's
    tree has punctured k, and re-deriving the leaf raises.
    """
    public, bundles = lecrv_deal(D=8, n=3)
    parties = make_parties(bundles)
    agg = LecrvAggregator(public=public)

    agg.sign(parties, key_id=2, msg=b"msg")

    from lecrv.seed_tree import derive_leaf
    for p in parties:
        with pytest.raises(ValueError):
            derive_leaf(p.tree, 2)


def test_verify_rejects_wrong_pk():
    public, bundles = lecrv_deal(D=4, n=3)
    parties = make_parties(bundles)
    agg = LecrvAggregator(public=public)
    sig = agg.sign(parties, key_id=1, msg=b"m")
    wrong_pk = public.one_time_pks[2]
    assert verify_with_pk(public.public_root, b"m", sig, wrong_pk) is False


def test_wrong_party_count_rejected():
    public, bundles = lecrv_deal(D=4, n=3)
    parties = make_parties(bundles)[:-1]
    agg = LecrvAggregator(public=public)
    with pytest.raises(ValueError):
        agg.sign(parties, key_id=0, msg=b"x")


def test_lecrv_matches_baseline_on_verification():
    """Signatures from both baseline and LE-CRV verify against the same
    verify_with_pk routine. This is a regression check on the goal:
    LE-CRV must not change the verifier."""
    from lecrv.threshold import Aggregator, Party, deal as baseline_deal

    # Baseline
    pub_b, bundles_b = baseline_deal(D=4, n=3)
    parties_b = [Party(bundle=b) for b in bundles_b]
    agg_b = Aggregator(public=pub_b)
    sig_b = agg_b.sign(parties_b, key_id=0, msg=b"same msg")
    pk_b = pub_b.one_time_pks[0]
    assert verify_with_pk(pub_b.public_root, b"same msg", sig_b, pk_b)

    # LE-CRV
    pub_l, bundles_l = lecrv_deal(D=4, n=3)
    parties_l = [LecrvParty(bundle=b) for b in bundles_l]
    agg_l = LecrvAggregator(public=pub_l)
    sig_l = agg_l.sign(parties_l, key_id=0, msg=b"same msg")
    pk_l = pub_l.one_time_pks[0]
    assert verify_with_pk(pub_l.public_root, b"same msg", sig_l, pk_l)


def test_storage_advantage_demonstrable():
    """LE-CRV party storage is dramatically smaller than the dealer's CRV.

    This is not a formal benchmark — it's a smoke test confirming the
    construction has the claimed storage asymmetry.
    """
    D, n = 64, 4
    public, bundles = lecrv_deal(D=D, n=n)

    from lecrv.seed_tree import storage_bytes

    per_party_bytes = storage_bytes(bundles[0].tree)

    # A single KeyID's correction table is 2 * NUM_BITS * 32 bytes.
    # Total CRV across D KeyIDs dwarfs the party's one seed.
    crv_bytes_per_key = 2 * NUM_BITS * 32
    total_crv_bytes = D * crv_bytes_per_key

    # Before any puncture, party has exactly one 32-byte seed.
    assert per_party_bytes == 32
    assert total_crv_bytes > 100 * per_party_bytes
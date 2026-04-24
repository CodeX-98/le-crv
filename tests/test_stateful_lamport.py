"""Tests for the stateful (D-time) Lamport scheme."""

import pytest

from lecrv import stateful_lamport as sl
from lecrv.stateful_lamport import (
    KeyExhaustedError,
    KeyReuseError,
    keygen,
    sign,
    verify_with_pk,
)


def test_keygen_requires_power_of_two():
    with pytest.raises(ValueError):
        keygen(3)
    with pytest.raises(ValueError):
        keygen(0)


def test_public_root_is_32_bytes():
    ck = keygen(4)
    assert len(ck.public_root) == 32


def test_sign_and_verify_single_message():
    ck = keygen(4)
    msg = b"hello"
    sig = sign(ck, msg)
    pk = ck.keypairs[sig.key_id].pk
    assert verify_with_pk(ck.public_root, msg, sig, pk) is True


def test_sign_uses_lowest_unused_key_id_by_default():
    ck = keygen(4)
    sig0 = sign(ck, b"m0")
    sig1 = sign(ck, b"m1")
    sig2 = sign(ck, b"m2")
    assert sig0.key_id == 0
    assert sig1.key_id == 1
    assert sig2.key_id == 2


def test_sign_refuses_reuse():
    ck = keygen(4)
    sign(ck, b"first")
    with pytest.raises(KeyReuseError):
        sign(ck, b"second", key_id=0)


def test_sign_exhausts_cleanly():
    D = 4
    ck = keygen(D)
    for i in range(D):
        sign(ck, f"msg{i}".encode())
    with pytest.raises(KeyExhaustedError):
        sign(ck, b"one too many")


def test_verify_rejects_wrong_message():
    ck = keygen(2)
    sig = sign(ck, b"real")
    pk = ck.keypairs[sig.key_id].pk
    assert verify_with_pk(ck.public_root, b"fake", sig, pk) is False


def test_verify_rejects_wrong_root():
    ck1 = keygen(2)
    ck2 = keygen(2)
    sig = sign(ck1, b"msg")
    pk = ck1.keypairs[sig.key_id].pk
    assert verify_with_pk(ck2.public_root, b"msg", sig, pk) is False


def test_verify_rejects_mismatched_pk():
    """Substituting a different one-time PK must cause verification to fail."""
    ck = keygen(4)
    sig = sign(ck, b"msg", key_id=1)
    other_pk = ck.keypairs[2].pk  # different slot
    assert verify_with_pk(ck.public_root, b"msg", sig, other_pk) is False


def test_explicit_key_id_is_respected():
    ck = keygen(8)
    sig = sign(ck, b"hi", key_id=5)
    assert sig.key_id == 5
    pk = ck.keypairs[5].pk
    assert verify_with_pk(ck.public_root, b"hi", sig, pk) is True


def test_out_of_range_key_id_rejected():
    ck = keygen(4)
    with pytest.raises(ValueError):
        sign(ck, b"x", key_id=4)


@pytest.mark.parametrize("D", [1, 2, 4, 8, 16])
def test_all_D_keys_usable(D):
    """For varying D, every KeyID can produce a valid signature."""
    ck = keygen(D)
    for i in range(D):
        sig = sign(ck, f"msg{i}".encode(), key_id=i)
        pk = ck.keypairs[i].pk
        assert verify_with_pk(ck.public_root, f"msg{i}".encode(), sig, pk)


def test_used_set_tracks_correctly():
    ck = keygen(4)
    assert ck.used == set()
    sign(ck, b"a", key_id=2)
    sign(ck, b"b", key_id=0)
    assert ck.used == {0, 2}


def test_verify_top_level_raises():
    """verify() (without PK) is not implemented; callers must use verify_with_pk."""
    ck = keygen(2)
    sig = sign(ck, b"m")
    with pytest.raises(NotImplementedError):
        sl.verify(ck.public_root, b"m", sig)
"""Baseline threshold demo: 3 parties jointly sign under one composite key."""

from lecrv.stateful_lamport import verify_with_pk
from lecrv.threshold import Aggregator, Party, deal


def main() -> None:
    D, n = 8, 3
    public, bundles = deal(D=D, n=n)
    parties = [Party(bundle=b) for b in bundles]
    agg = Aggregator(public=public)

    print(f"Dealt D={D} one-time keys across n={n} parties")
    print(f"Public root: {public.public_root.hex()}\n")

    for key_id, msg in enumerate([b"alpha", b"bravo", b"charlie"]):
        sig = agg.sign(parties, key_id=key_id, msg=msg)
        pk = public.one_time_pks[sig.key_id]
        ok = verify_with_pk(public.public_root, msg, sig, pk)
        print(f"  KeyID {sig.key_id}: {msg!r} -> verified: {ok}")


if __name__ == "__main__":
    main()
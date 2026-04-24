"""LE-CRV demo: 3 parties sign via seed trees + public CRV."""

from lecrv.seed_tree import storage_bytes
from lecrv.stateful_lamport import verify_with_pk
from lecrv.threshold import LecrvAggregator, LecrvParty, lecrv_deal


def main() -> None:
    D, n = 16, 3
    public, bundles = lecrv_deal(D=D, n=n)
    parties = [LecrvParty(bundle=b) for b in bundles]
    agg = LecrvAggregator(public=public)

    print(f"LE-CRV setup: D={D}, n={n}, d={public.d}")
    print(f"Public root:   {public.public_root.hex()}")
    print(f"Party 0 init storage: {storage_bytes(parties[0].tree)} bytes\n")

    for key_id, msg in enumerate([b"alpha", b"bravo", b"charlie", b"delta"]):
        sig = agg.sign(parties, key_id=key_id, msg=msg)
        pk = public.one_time_pks[sig.key_id]
        ok = verify_with_pk(public.public_root, msg, sig, pk)
        print(
            f"  KeyID {sig.key_id}: {msg!r:10} -> verified: {ok}, "
            f"party-0 storage now: {storage_bytes(parties[0].tree)} bytes"
        )


if __name__ == "__main__":
    main()
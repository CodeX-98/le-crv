"""Threshold layer: three schemes for direct comparison.

- Naive baseline:    O(D) per-party storage, no forward security.
- Kelsey-Lang-Lucks 2025:     O(1) per-party storage, no forward security.
- LE-CRV (this work):         O(log D * p) per-party storage, FORWARD-SECURE.
"""

from lecrv.stateful_lamport import verify_with_pk

# Naive baseline.
from lecrv.threshold.aggregator import Aggregator
from lecrv.threshold.dealer import PartyShareBundle, PublicMaterial, deal
from lecrv.threshold.party import Party

# Kelsey-Lang-Lucks 2025 style.
from lecrv.threshold.kelsey_aggregator import KelseyAggregator
from lecrv.threshold.kelsey_dealer import (
    KelseyCRV,
    KelseyPartyBundle,
    KelseyPublic,
)
from lecrv.threshold.kelsey_dealer import deal as kelsey_deal
from lecrv.threshold.kelsey_party import KelseyParty

# LE-CRV (our contribution).
from lecrv.threshold.lecrv_aggregator import LecrvAggregator
from lecrv.threshold.lecrv_dealer import (
    CommonReferenceValue,
    LecrvPartyBundle,
    LecrvPublic,
)
from lecrv.threshold.lecrv_dealer import deal as lecrv_deal
from lecrv.threshold.lecrv_party import LecrvParty

__all__ = [
    # Baseline
    "Aggregator", "Party", "PartyShareBundle", "PublicMaterial", "deal",
    # Kelsey
    "KelseyAggregator", "KelseyParty", "KelseyPartyBundle", "KelseyPublic",
    "KelseyCRV", "kelsey_deal",
    # LE-CRV
    "LecrvAggregator", "LecrvParty", "LecrvPartyBundle", "LecrvPublic",
    "CommonReferenceValue", "lecrv_deal",
    # Common
    "verify_with_pk",
]
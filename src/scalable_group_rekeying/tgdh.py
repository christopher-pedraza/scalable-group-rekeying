# @Chris

"""IMPORTANT

The DH rule only works if every parent is published as a BlindedKey with its children,
including the root. TGDH doesn't normally need the root's blinded key, and the _apply
docstring doesn't clearly require it. Without it, closure never derives the root secret,
so members would show false REACHABILITY violations and real leaks of the group key
would go unnoticed. Every parent, including the root, must be published as a BlindedKey
with its children
"""

from collections.abc import Sequence

from scalable_group_rekeying.scheme import DeliveryResult, RekeyScheme
from scalable_group_rekeying.types import (
    Batch,
    KeyRef,
    MemberId,
    RekeyMessage,
    Snapshot,
)


class TGDH(RekeyScheme):
    name = "tgdh"
    supports_batch = False

    def _init(self, batch: Batch) -> Sequence[RekeyMessage]:
        raise NotImplementedError

    def _apply(self, batch: Batch) -> Sequence[RekeyMessage]:
        raise NotImplementedError

    def members(self) -> frozenset[MemberId]:
        raise NotImplementedError

    def group_key(self) -> tuple[KeyRef, bytes]:
        raise NotImplementedError

    def height(self) -> int:
        raise NotImplementedError

    def deliver(self, member: MemberId, msg: RekeyMessage) -> DeliveryResult:
        raise NotImplementedError

    def member_group_key(self, member: MemberId) -> tuple[KeyRef, bytes] | None:
        raise NotImplementedError

    def snapshot(self, viewer: MemberId | None = None) -> Snapshot:
        raise NotImplementedError

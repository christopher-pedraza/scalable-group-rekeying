# @Zeyad

from collections.abc import Sequence

from scalable_group_rekeying.scheme import DeliveryResult, RekeyScheme
from scalable_group_rekeying.types import (
    Batch,
    KeyRef,
    MemberId,
    RekeyMessage,
    Snapshot,
)


class LKH(RekeyScheme):
    name = "lkh"
    supports_batch = True

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

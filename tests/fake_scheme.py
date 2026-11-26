"""Minimal schemes used to test the logic shared by all schemes in RekeyScheme."""

from collections.abc import Sequence

from scalable_group_rekeying.scheme import DeliveryResult, RekeyScheme
from scalable_group_rekeying.types import (
    Batch,
    EventKind,
    KeyRef,
    MemberId,
    RekeyMessage,
    SchemeConfig,
    Snapshot,
)


class FakeScheme(RekeyScheme):
    """Only tracks membership and sends one signed, empty message per batch."""

    name = "fake"

    def __init__(self, config: SchemeConfig) -> None:
        super().__init__(config)
        self.current: set[MemberId] = set()
        self.calls: list[str] = []  # which hooks ran, in order

    def _init(self, batch: Batch) -> Sequence[RekeyMessage]:
        self.calls.append("init")
        return self._change(batch)

    def _apply(self, batch: Batch) -> Sequence[RekeyMessage]:
        self.calls.append("apply")
        return self._change(batch)

    def _change(self, batch: Batch) -> Sequence[RekeyMessage]:
        for event in batch.events:
            if event.kind == EventKind.LEAVE:
                self.current.remove(event.member)
            else:
                self.current.add(event.member)
        return [self._signed(RekeyMessage(self.epoch, sender=None))]

    def members(self) -> frozenset[MemberId]:
        return frozenset(self.current)

    def height(self) -> int:
        return 1

    def group_key(self) -> tuple[KeyRef, bytes]:
        raise NotImplementedError

    def deliver(self, member: MemberId, msg: RekeyMessage) -> DeliveryResult:
        raise NotImplementedError

    def member_group_key(self, member: MemberId) -> tuple[KeyRef, bytes] | None:
        raise NotImplementedError

    def snapshot(self, viewer: MemberId | None = None) -> Snapshot:
        raise NotImplementedError


class BatchFakeScheme(FakeScheme):
    supports_batch = True


class BusyScheme(FakeScheme):
    """Uses every shared crypto helper, so runs can be compared with each other."""

    def _change(self, batch: Batch) -> Sequence[RekeyMessage]:
        super()._change(batch)
        wrapper, payload = KeyRef(self._next_node(), 0), KeyRef(self._next_node(), 0)
        wrapper_key, payload_key = self.keys.key(), self.keys.key()
        wrapped = self._wrap(wrapper, wrapper_key, [(payload, payload_key)])
        message = self._signed(RekeyMessage(self.epoch, sender=None, wraps=(wrapped,)))
        for member in sorted(self.members()):
            assert self._signature_ok(message)
            assert self._unwrap(wrapped, wrapper_key, message.epoch) == (payload_key,)
            self._modexp(member, 4, 12345, self.config.dh.p)
        return [message]

from collections import Counter
from collections.abc import Sequence

from scalable_group_rekeying.crypto import message_bytes
from scalable_group_rekeying.types import (
    Batch,
    Epoch,
    EventCost,
    EventKind,
    MemberId,
    RekeyMessage,
)


class CostCounter:
    """Collects the costs of one batch. Create a new one for each batch."""

    def __init__(self) -> None:
        self._wraps = 0
        self._unwraps = 0
        # need to track per member for modexp_serial (max over actors)
        self._modexps: Counter[MemberId] = Counter()

    def add_wrap(self) -> None:
        """Records one AEAD encryption."""
        self._wraps += 1

    def add_unwrap(self) -> None:
        """Records one successful member-side decryption."""
        self._unwraps += 1

    def add_modexp(self, actor: MemberId) -> None:
        """Records one modular exponentiation done by actor."""
        self._modexps[actor] += 1

    def finish(
        self,
        *,
        epoch: Epoch,
        batch: Batch,
        members_before: int,
        height: int,
        messages: Sequence[RekeyMessage],
    ) -> EventCost:
        """Builds the cost row for this batch. Doesn't modify the counters."""
        joining = (EventKind.JOIN, EventKind.REJOIN)
        multicast = sum(m.recipient is None for m in messages)
        return EventCost(
            epoch=epoch,
            n_joins=sum(e.kind in joining for e in batch.events),
            n_leaves=sum(e.kind is EventKind.LEAVE for e in batch.events),
            members_before=members_before,
            height=height,
            messages_multicast=multicast,
            messages_unicast=len(messages) - multicast,
            wraps=self._wraps,
            key_encryptions=sum(len(w.payloads) for m in messages for w in m.wraps),
            unwraps=self._unwraps,
            bytes_on_wire=sum(
                len(message_bytes(m)) + len(m.signature) for m in messages
            ),
            modexp_total=self._modexps.total(),
            modexp_serial=max(self._modexps.values(), default=0),
        )

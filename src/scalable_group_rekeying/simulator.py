"""Runs batches on a scheme and records what the verifier and the games need."""

from collections.abc import Iterable, Sequence
from typing import Protocol

from scalable_group_rekeying.crypto import seal
from scalable_group_rekeying.scheme import RekeyOutcome, RekeyScheme
from scalable_group_rekeying.types import (
    Batch,
    DataMessage,
    EpochRecord,
    EventKind,
    MemberId,
    Transcript,
)


class Observer(Protocol):
    """Anything that wants to look at the state after each batch. It gets only
    lower-layer types, so the verifier never has to import this module."""

    def after_apply(
        self,
        scheme: RekeyScheme,
        outcome: RekeyOutcome,
        transcript: Transcript,
        epochs: Sequence[EpochRecord],
    ) -> None: ...


class Simulator:
    def __init__(self, scheme: RekeyScheme, observers: Sequence[Observer] = ()) -> None:
        self.scheme = scheme
        self.observers = tuple(observers)
        self.transcript = Transcript()  # public: what an eavesdropper sees
        self.epochs: list[EpochRecord] = []  # private truth, index = epoch

    def init(self, members: Sequence[MemberId]) -> RekeyOutcome:
        """Creates the group and records epoch 0."""
        outcome = self.scheme.init(members)
        self._record(outcome)
        return outcome

    def apply(self, batch: Batch) -> RekeyOutcome:
        """Applies one batch and records it."""
        if not self.epochs:
            raise RuntimeError("init() must be called before apply()")
        outcome = self.scheme.apply(batch)
        self._record(outcome)
        return outcome

    def run(self, batches: Iterable[Batch]) -> list[RekeyOutcome]:
        """Applies the batches in order."""
        return [self.apply(batch) for batch in batches]

    def _record(self, outcome: RekeyOutcome) -> None:
        """Adds the messages to the transcript, updates the membership from the events
        (not from the scheme), stores the EpochRecord, seals one probe message with
        scheme.keys.nonce(), and calls the observers.

        It's a bookkeeping function, by the time it runs, the rekeying already happened.
        """
        # Check that nothing was missed
        epoch = outcome.epoch
        if epoch != len(self.epochs):
            raise RuntimeError("the scheme was changed outside the simulator")

        # Adds to the transcript the messages that are sent over the wire
        # The transcript is public as it's what an eavesdropper sees.
        self.transcript.rekeys.extend(outcome.messages)  # keeps messages in send order

        # Membership replay instead of relying on what the scheme reports it has as
        # memebers. This way we can test the scheme implementation against computing the
        # membership from the events.
        events = outcome.batch.events
        leaving = {e.member for e in events if e.kind is EventKind.LEAVE}
        joining = {
            e.member for e in events if e.kind is not EventKind.LEAVE
        }  # re-/join
        previous = self.epochs[-1].members if self.epochs else frozenset()
        members = (previous - leaving) | joining

        # Epoch record: contains the ground truth. Used by the verifier to know whether
        # an adversary recovered the real key
        group_ref, group_key = self.scheme.group_key()
        self.epochs.append(
            EpochRecord(epoch, outcome.batch, members, group_ref, group_key)
        )

        # Test message to imitate group chatting
        probe = f"probe {epoch}".encode()  # Application traffic
        blob = seal(
            group_key, probe, epoch, self.scheme.keys.nonce()
        )  # Binds the ciphertext to the epoch
        self.transcript.data.append(DataMessage(epoch, blob))

        # Run last so they see a complete record for the current epoch, including epoch
        # 0. Receive a list.
        for observer in self.observers:
            observer.after_apply(self.scheme, outcome, self.transcript, self.epochs)

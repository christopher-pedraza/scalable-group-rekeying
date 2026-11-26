# TODO: @Chris
"""Runs batches on a scheme and records what the verifier and the games need."""

from collections.abc import Iterable, Sequence
from typing import Protocol

from scalable_group_rekeying.scheme import RekeyOutcome, RekeyScheme
from scalable_group_rekeying.types import Batch, EpochRecord, MemberId, Transcript


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
        raise NotImplementedError

    def apply(self, batch: Batch) -> RekeyOutcome:
        """Applies one batch and records it."""
        raise NotImplementedError

    def run(self, batches: Iterable[Batch]) -> list[RekeyOutcome]:
        """Applies the batches in order."""
        raise NotImplementedError

    def _record(self, outcome: RekeyOutcome) -> None:
        """Adds the messages to the transcript, updates the membership from the events
        (not from the scheme), stores the EpochRecord, seals one probe message with
        scheme.keys.nonce(), and calls the observers."""
        raise NotImplementedError

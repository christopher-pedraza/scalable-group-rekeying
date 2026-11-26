# TODO: @Zeyad
# Basically, it generates random but valid events with timestamps, reproducible from
# a seed, and groups them into batches. It's just the input, it doesn't run anything.
# This way we can generate these random join, leave, etc events and test "real"
# scenarios in our schemes. I will also use this to generate the input for my
# experiments
"""Seeded membership workloads. The same arguments give the same events, so every
scheme is compared on identical input."""

from collections.abc import Sequence

from scalable_group_rekeying.types import Batch, Event, MemberId


def random_events(
    initial: Sequence[MemberId], n_events: int, seed: int, *, rate: float = 1.0
) -> list[Event]:
    """Returns n_events valid events for a group that starts with `initial`.

    - seq counts up from len(initial), because init() uses the numbers before it
    - time never decreases; `rate` is the average number of events per time unit
    - JOIN uses a new id (>= 1), LEAVE a current member, REJOIN a former member
    - the group never becomes empty
    - randomness comes from its own random.Random(seed)
    """
    raise NotImplementedError


def batch_by_interval(events: Sequence[Event], interval: float) -> list[Batch]:
    """Collects the events of each interval into one batch, applied at its end.

    Empty intervals give no batch. Every batch must be accepted by apply():
    - no member appears twice (decide what to do with a join and leave of the same
      member inside one interval)
    - at least one current member stays
    - no event is later than t_apply
    """
    raise NotImplementedError

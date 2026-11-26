from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, StrEnum
from typing import NewType

MemberId = NewType("MemberId", int)  # ids ≥ 1, never reused for a different person
Epoch = NewType("Epoch", int)  # 0 = initial group; +1 per applied batch


# ---------- keys and key rings ----------


@dataclass(frozen=True, slots=True, order=True)
class KeyRef:
    """Identifier for keys without revealing the keys. Includes a version that gets
    bumped on every replacement. Node ids are assigned by the scheme from a monotonic
    counter and are never reused"""

    node: int
    version: int


@dataclass(frozen=True, slots=True)
class Acquisition:
    """When the key was learned."""

    ref: KeyRef
    key: bytes  # TGDH secrets are stored as big-endian bytes of the exponent
    epoch: Epoch


@dataclass(slots=True)
class KeyRing:
    """Everything one person has ever held, across all stints (every time it has been a
    member). It should be append-only; ex-members keep every key and when rejoining,
    because the ring belongs to the person, the old-stint keys stay in history while
    new keys are added"""

    member: MemberId
    # What the person learns and when. Lets you filter by epoch
    history: list[Acquisition] = field(default_factory=list)
    # Lookup table to answer if the person holds a certain key and what are its bytes
    _index: dict[KeyRef, bytes] = field(default_factory=dict, init=False, repr=False)

    def learn(self, ref: KeyRef, key: bytes, epoch: Epoch) -> None:
        """Member learns a new key"""
        self.history.append(Acquisition(ref, key, epoch))
        self._index[ref] = key

    def get(self, ref: KeyRef) -> bytes | None:
        """Retrieve one of the learned keys"""
        return self._index.get(ref)

    def ever_held(
        self,
    ) -> dict[KeyRef, bytes]:
        """Returns everything the person has ever been given over their whole history"""
        return dict(self._index)


# ---------- membership events ----------


class EventKind(StrEnum):
    """Membership events that trigger a rekey"""

    JOIN = "join"  # the initial group at epoch 0 is a batch of JOINs at time 0
    LEAVE = "leave"
    REJOIN = "rejoin"  # Tells the verifier to check for old-stint keys staying useless


@dataclass(frozen=True, slots=True)
class Event:
    """Unit of input for the workload generator."""

    seq: int
    kind: EventKind
    member: MemberId
    time: float = 0.0  # the moment the event is requested


@dataclass(frozen=True, slots=True)
class Batch:
    """One atomic rekey. A single event is a Batch of one. A batch never contains two
    events for the same member."""

    events: tuple[Event, ...]
    # For a single rekeying event t_apply = event.time.
    # For a batch of multiple events, the controller collects events inside an interval
    # and then applies the rekey at t_apply only once for all events.
    # The period t_apply-event.time is the vulnerability window.
    t_apply: float

    @classmethod
    def single(cls, e: Event) -> "Batch":
        return cls((e,), e.time)


# ---------- rekey messages (public) ----------


@dataclass(frozen=True, slots=True)
class Wrap:
    """One or more keys encrypted under another key."""

    wrapper: KeyRef
    payloads: tuple[KeyRef, ...]
    blob: bytes


@dataclass(frozen=True, slots=True)
class BlindedKey:
    """A TGDH public value a^key mod p, with the refs of its two children."""

    node: KeyRef
    bk: bytes
    # If it's a leaf, children is empty. Otherwise, they are the two nodes that were
    # combined to compute this BK. Lets the verifier apply the DH rule without importing
    # the TGDH code.
    children: tuple[KeyRef, ...] = ()


@dataclass(frozen=True, slots=True)
class RekeyMessage:
    """A single broadcast or unicast message with the new keys."""

    epoch: Epoch  # the epoch this message helps create
    sender: MemberId | None  # None = group controller (Star/LKH)
    recipient: MemberId | None = None  # None = multicast to the group; else unicast
    wraps: tuple[Wrap, ...] = ()  # Star / LKH
    blinded: tuple[BlindedKey, ...] = ()  # TGDH
    signature: bytes = b""  # Ed25519; b"" = unsigned


@dataclass(frozen=True, slots=True)
class DataMessage:
    """Probe traffic (application data) sealed using the current epoch's group key."""

    epoch: Epoch
    blob: bytes


@dataclass(slots=True)
class Transcript:
    """All rekey and adata messages ever sent (what a pasive eavesdropper sees)."""

    rekeys: list[RekeyMessage] = field(default_factory=list)
    data: list[DataMessage] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class EpochRecord:
    """Contains what the simulator knows about the group at a given epoch. It's how the
    verifier judges a result (can prove if the adversary recovered the key by having the
    real key to compare against)"""

    epoch: Epoch
    batch: Batch
    # The member list cannot come from the tree because that's being tested. The
    # verifier needs the source of truth and the tree could have a bug and corrupt
    # the answer. Thus, the membership is replayed from the events: the simulator
    # keeps a plain set and applies each event so the verifier can compare and find
    # the mismatch.
    members: frozenset[
        MemberId
    ]  # replayed from events by the simulator, not read from the tree
    group_ref: KeyRef
    group_key: bytes


# ---------- cost metrics ----------


@dataclass(frozen=True, slots=True)
class EventCost:
    """One row of measurements per applied batch"""

    epoch: Epoch
    n_joins: int  # joins and rejoins
    n_leaves: int
    members_before: int  # after = before + joins - leaves
    height: int  # tree height after the event (Star = 1; LKH/TGDH = root->deepest leaf)
    # --- messages / symmetric crypto (Star, LKH) ---
    messages_multicast: int  # messages with recipient None
    messages_unicast: int  # messages with a recipient
    wraps: int  # AEAD calls (ciphertexts)
    key_encryptions: int  # Wong units: Σ len(payloads)
    unwraps: int  # member-side decryption attempts that succeeded
    bytes_on_wire: int  # encoded messages + signatures; each message counted once
    # --- public key (TGDH) ---
    modexp_total: int  # sum exponentiations over all actors
    modexp_serial: int  # max exponentiation over any single member


# ---------- configuration ----------


class Fault(StrEnum):
    """Tag to flag deliberately broken rekeying"""

    NONE = "none"
    STALE_KEY_REUSE = "stale_key_reuse"  # a key that must change is reused
    WRAP_UNDER_DEPARTED = "wrap_under_departed"  # key wrapped under key leaver holds
    SKIP_ANCESTOR = "skip_ancestor"  # ancestor on the path not rekeyed
    NO_SPONSOR_REFRESH = "no_sponsor_refresh"  # TGDH: sponsor keeps its old share


@dataclass(frozen=True, slots=True)
class DHParams:
    """Parameters for the Diffie-Hellman group used in TGDH"""

    p: int
    q: int  # order of the subgroup, p = 2q+1
    alpha: int  # generator of that subgroup


# Toy group for experiments: 65-bit safe prime p = 2q+1 (NOT secure, only cheap).
# alpha = 4 = 2^2 is a quadratic residue, so it generates the order-q subgroup.
DH_TOY = DHParams(
    p=18446744073709554719,
    q=9223372036854777359,
    alpha=4,
)

# Standard 2048-bit MODP group (RFC 3526, group 14) for the demo.
# p is a safe prime and p = 7 (mod 8), so alpha = 2 is a quadratic residue and has
# order q = (p-1)/2.
_MODP_2048_P = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
    16,
)
DH_MODP = DHParams(p=_MODP_2048_P, q=(_MODP_2048_P - 1) // 2, alpha=2)


@dataclass(frozen=True, slots=True)
class SchemeConfig:
    """Parameters that control the simulator's behavior"""

    seed: int | None = None
    degree: int = 4  # LKH only
    dh: DHParams = DH_TOY  # TGDH only
    fault: Fault = Fault.NONE
    sign: bool = True  # whether rekey messages are signed
    cache: bool = True  # reuse repeated work; set False when measuring running time


# ---------- tree snapshots (what the UI draws) ----------


@dataclass(frozen=True, slots=True)
class NodeSnapshot:
    """One tree node shape the UI can draw using only fingerprints, without revealing
    the keys."""

    id: int
    parent: int | None
    children: tuple[
        int, ...
    ]  # Star: root->leaves. LKH: ≤ d. TGDH: exactly 0 (leaf) or 2
    member: MemberId | None  # set on leaves
    size: int  # members below this node; root = n, leaves = 1
    version: int  # version of this node's current key; KeyRef(id, version) names it
    key_fp: str  # first 8 hex chars of SHA-256(key); NEVER the key itself
    bk_fp: str | None = None  # TGDH only (public anyway)
    changed: bool = False  # rekeyed by the last batch
    held: bool = False  # `viewer` holds this node's secret
    on_copath: bool = (
        False  # TGDH: sibling of a node on viewer's path (its BK is stored by viewer)
    )
    is_sponsor: bool = False  # TGDH: leaf of the sponsor for the last event


@dataclass(frozen=True, slots=True)
class WrapEdge:
    """{payload}_{wrapper} as an arrow, so the UI can animate 'who learns what from
    which wrap'."""

    wrapper: int
    payload: int


@dataclass(frozen=True, slots=True)
class Snapshot:
    """The whole tree at one epoch, from one viewer's perspective."""

    scheme: str  # "star" | "lkh" | "tgdh"
    epoch: Epoch
    root: int
    nodes: tuple[NodeSnapshot, ...]  # flat list, parent/children by id
    viewer: (
        MemberId | None
    )  # None = global/controller view. Else `held`/`on_copath` are for them
    last_event: str  # e.g. "leave u7", for the UI caption
    wrap_edges: tuple[
        WrapEdge, ...
    ] = ()  # Star/LKH: arrows of the last rekey message(s)
    cost: EventCost | None = None

    @property
    def members(self) -> tuple[MemberId, ...]:
        """Derived from the leaves, not stored. to_jsonable() includes it for the UI's
        "view as" dropdown."""
        return tuple(sorted(n.member for n in self.nodes if n.member is not None))


def to_jsonable(obj: object) -> object:
    """dataclass/enum/bytes/tuple/frozenset -> plain JSON types (bytes->hex,
    sets->sorted lists, large ints->strings). Raises TypeError for any other type."""
    if isinstance(obj, Enum):  # checked first, because a StrEnum is also a str
        return obj.value
    if isinstance(obj, int) and abs(obj) > 2**53 - 1:
        return str(obj)  # JavaScript would round it, so convert it to string
    if obj is None or isinstance(obj, bool | int | float | str):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, tuple | list):
        return [to_jsonable(item) for item in obj]
    if isinstance(obj, set | frozenset):
        return [to_jsonable(item) for item in sorted(obj)]
    if is_dataclass(obj) and not isinstance(obj, type):  # an instance, not a class
        result = {f.name: to_jsonable(getattr(obj, f.name)) for f in fields(obj)}
        if isinstance(obj, Snapshot):  # members is a property, not a field
            result["members"] = to_jsonable(obj.members)
        return result
    raise TypeError(f"cannot convert {type(obj).__name__} to JSON")

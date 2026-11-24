# TODO: I just defined the interface here, we need to implement each of the functions
# I wrote a small comment on each function to roughly explain what I planned it to do
# You may change them as you wish Zeyad

from scalable_group_rekeying.types import Epoch, KeyRef

KEY_LEN, NONCE_LEN, TAG_LEN = 32, 16, 32


class KeySource:
    """Defines the randomness of the project."""

    def __init__(self, seed: int | None = None) -> None: ...
    def key(self) -> bytes: ...  # creates new key trees
    def nonce(self) -> bytes: ...  # supplies each warp's nounce
    def exponent(
        self, q: int
    ) -> int: ...  # create TGDH private sharesu (uniform in [2, q-1])


def wrap_context(
    wrapper: KeyRef, payloads: tuple[KeyRef, ...], epoch: Epoch
) -> bytes: ...  # who wraps what and in which epoch
def wrap(
    key: bytes, payload: bytes, context: bytes, nonce: bytes
) -> bytes: ...  # nonce ‖ ct ‖ tag
def unwrap(
    key: bytes, blob: bytes, context: bytes
) -> (
    bytes | None
): ...  # Recomputes the tag and compares with hmac digest. None on ANY failure
def wrap_len(
    n_payloads: int,
) -> int: ...  # exact blob size for a given num of payloads


# The same primitives of wrap and unwrap, but for data messages under the epoch's group
# key
def seal(group_key: bytes, plaintext: bytes, epoch: Epoch, nonce: bytes) -> bytes: ...
def open_sealed(group_key: bytes, blob: bytes, epoch: Epoch) -> bytes | None: ...


# Converts between integers (for secrets) and bytes (for keyring)
def int_to_key(x: int, nbytes: int) -> bytes: ...  # TGDH exponent ↔ ring bytes
def key_to_int(b: bytes) -> int: ...
def derive_group_key(
    root_secret: int, label: bytes
) -> bytes: ...  # hash the DH value, never use it raw

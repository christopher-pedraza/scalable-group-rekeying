# TODO: I just defined the interface here, we need to implement each of the functions
# I wrote a small comment on each function to roughly explain what I planned it to do
# You may change them as you wish Zeyad
import random
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,  # noqa: F401 TODO: REMOVE this ignore
    Ed25519PublicKey,  # noqa: F401 TODO: REMOVE this ignore
)

from scalable_group_rekeying.types import Epoch, KeyRef, RekeyMessage

KEY_LEN, NONCE_LEN, TAG_LEN = 32, 16, 32
SIG_KEY_LEN, SIG_LEN = 32, 64


class KeySource:
    """Defines the randomness of the project.

    When seed=none, uses the OS CSPRNG, otherwise uses a seeded PRNG for reproducible
    testing.
    """

    def __init__(self, seed: int | None = None) -> None:
        # Define the generators
        self._keys = self._stream(seed, "key")
        self._nonces = self._stream(seed, "nonce")
        self._signing_keys = self._stream(seed, "sign")
        self._exponents = self._stream(seed, "exponent")

    def key(self) -> bytes:
        """Fresh symmetric key"""
        return self._keys.randbytes(KEY_LEN)

    def nonce(self) -> bytes:
        """Fresh nonce for one wrap or sealed message. Should never be reused with the
        same key."""
        return self._nonces.randbytes(NONCE_LEN)

    def signing_key(self) -> bytes:
        """Fresh signing key"""
        return self._signing_keys.randbytes(SIG_KEY_LEN)

    def exponent(self, q: int) -> int:
        """TGDH private share, uniform in [2, q-1]"""

        # If exp is:
        # 0 -> BK = 1
        # 1 -> BK = alpha
        # >= q -> BK repeats 0, 1...
        return self._exponents.randrange(
            2, q
        )  # needs int in this range instead of fixed num of bytes

    @staticmethod  # <- Doesn't depend on the instance
    def _stream(seed: int | None, label: str) -> random.Random:
        if seed is None:
            return secrets.SystemRandom()
        return random.Random(f"{seed}:{label}")  # append label to avoid collision


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


# signatures (thin wrappers over cryptography's Ed25519)
def public_key(
    signing_key: bytes,
) -> bytes: ...  # signing_key = SIG_KEY_LEN bytes from KeySource.key()
def sign(signing_key: bytes, data: bytes) -> bytes: ...  # SIG_LEN bytes, deterministic
def verify(
    public_key: bytes, data: bytes, signature: bytes
) -> bool: ...  # False on ANY failure, never raises
def message_bytes(
    msg: RekeyMessage,
) -> bytes: ...  # what gets signed: every field except `signature`

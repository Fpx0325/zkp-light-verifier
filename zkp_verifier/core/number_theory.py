"""Fixed group and Fiat–Shamir challenge encoding shared by both parties."""

from hashlib import sha256
from secrets import randbelow

# The ffdhe2048 group from RFC 7919, Appendix A.1.
P = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
    "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
    "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
    "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
    "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
    "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
    "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
    "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
    "886B423861285C97FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
G = 2
FIELD_BYTES = 256
SCHEME = "schnorr-ffdhe2048-sha256-v1"
MAX_CONTEXT_BYTES = 256


def sample_scalar() -> int:
    return 1 + randbelow(Q - 1)


def is_subgroup_element(value: int) -> bool:
    return 1 < value < P and pow(value, Q, P) == 1


def context_bytes(context: str) -> bytes:
    if not isinstance(context, str):
        raise ValueError("Context must be text.")
    encoded = context.encode("utf-8")
    if not 1 <= len(encoded) <= MAX_CONTEXT_BYTES:
        raise ValueError(f"Context must be 1 to {MAX_CONTEXT_BYTES} UTF-8 bytes.")
    return encoded


def challenge(public_value: int, commitment: int, context: str) -> int:
    transcript = (
        SCHEME.encode("ascii") + b"\x00"
        + public_value.to_bytes(FIELD_BYTES, "big")
        + commitment.to_bytes(FIELD_BYTES, "big")
        + context_bytes(context)
    )
    return int.from_bytes(sha256(transcript).digest(), "big")

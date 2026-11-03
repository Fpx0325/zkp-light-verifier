"""Generate a private scalar and derive the corresponding public value."""

from .number_theory import G, P, Q, sample_scalar


def generate_secret() -> int:
    return sample_scalar()


def derive_public_value(secret: int) -> int:
    if type(secret) is not int or not 1 <= secret < Q:
        raise ValueError("Secret must be an integer in [1, q).")
    return pow(G, secret, P)

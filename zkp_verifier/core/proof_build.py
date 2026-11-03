"""Construct a proof using a fresh random nonce."""

from dataclasses import dataclass

from .number_theory import G, P, Q, challenge, sample_scalar
from .secret_gen import derive_public_value


@dataclass(frozen=True)
class Proof:
    commitment: int
    response: int


def create_proof(secret: int, context: str) -> tuple[int, Proof]:
    public_value = derive_public_value(secret)
    nonce = sample_scalar()
    commitment = pow(G, nonce, P)
    response = (nonce - challenge(public_value, commitment, context) * secret) % Q
    return public_value, Proof(commitment, response)

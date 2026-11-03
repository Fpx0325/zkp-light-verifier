"""Check the Schnorr relation with an independently supplied statement."""

from dataclasses import dataclass
from enum import Enum

from .number_theory import G, P, Q, challenge, is_subgroup_element
from .proof_build import Proof


@dataclass(frozen=True)
class VerificationInput:
    public_value: int
    context: str
    proof: Proof


class Verdict(str, Enum):
    VERIFIED = "verified"
    INVALID_PUBLIC_VALUE = "invalid_public_value"
    INVALID_COMMITMENT = "invalid_commitment"
    INVALID_RESPONSE = "invalid_response"
    EQUATION_MISMATCH = "equation_mismatch"


def verify(item: VerificationInput) -> Verdict:
    if not is_subgroup_element(item.public_value):
        return Verdict.INVALID_PUBLIC_VALUE
    commitment, response = item.proof.commitment, item.proof.response
    if not 1 < commitment < P:
        return Verdict.INVALID_COMMITMENT
    if not 0 <= response < Q:
        return Verdict.INVALID_RESPONSE

    c = challenge(item.public_value, commitment, item.context)
    reconstructed = pow(G, response, P) * pow(item.public_value, c, P) % P
    # Equality also establishes that the commitment is in the subgroup.
    return Verdict.VERIFIED if reconstructed == commitment else Verdict.EQUATION_MISMATCH

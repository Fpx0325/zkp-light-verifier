"""Validate public request fields before invoking the verifier."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..config import MAX_BATCH_SIZE
from ..core.number_theory import MAX_CONTEXT_BYTES, SCHEME, context_bytes
from ..core.verify_logic import VerificationInput
from ..proof_io import HEX_PATTERN, HEX_WIDTH, parse_item

HexValue = Annotated[str, Field(min_length=HEX_WIDTH, max_length=HEX_WIDTH, pattern=f"^{HEX_PATTERN}$")]


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ProofBody(StrictBody):
    scheme: Literal[SCHEME]
    commitment: HexValue
    response: HexValue


class VerificationBody(StrictBody):
    public_value: HexValue
    context: Annotated[str, Field(min_length=1, max_length=MAX_CONTEXT_BYTES)]
    proof: ProofBody

    @field_validator("context")
    @classmethod
    def validate_context(cls, value: str) -> str:
        context_bytes(value)
        return value

    def to_input(self) -> VerificationInput:
        return parse_item(self.model_dump())


class BatchBody(StrictBody):
    items: Annotated[list[VerificationBody], Field(min_length=1, max_length=MAX_BATCH_SIZE)]

"""Read and write the stable public proof format."""

import json
import re
from pathlib import Path
from tempfile import NamedTemporaryFile

from .config import MAX_BODY_BYTES
from .core.number_theory import FIELD_BYTES, SCHEME, context_bytes
from .core.proof_build import Proof
from .core.verify_logic import VerificationInput

HEX_WIDTH = FIELD_BYTES * 2
HEX_PATTERN = rf"[0-9a-f]{{{HEX_WIDTH}}}"
MAX_PROOF_BYTES = 4096


def to_hex(value: int) -> str:
    return format(value, f"0{HEX_WIDTH}x")


def from_hex(value: object) -> int:
    if not isinstance(value, str) or re.fullmatch(HEX_PATTERN, value) is None:
        raise ValueError(f"Expected {HEX_WIDTH} lowercase hexadecimal digits.")
    return int(value, 16)


def proof_payload(proof: Proof) -> dict[str, str]:
    return {
        "scheme": SCHEME,
        "commitment": to_hex(proof.commitment),
        "response": to_hex(proof.response),
    }


def parse_proof(payload: object) -> Proof:
    if not isinstance(payload, dict) or payload.keys() != {"scheme", "commitment", "response"}:
        raise ValueError("Proof must contain scheme, commitment and response.")
    if payload["scheme"] != SCHEME:
        raise ValueError("Unsupported proof scheme.")
    return Proof(from_hex(payload["commitment"]), from_hex(payload["response"]))


def parse_item(payload: object) -> VerificationInput:
    if not isinstance(payload, dict) or payload.keys() != {"public_value", "context", "proof"}:
        raise ValueError("Each item must contain public_value, context and proof.")
    context = payload["context"]
    context_bytes(context)
    return VerificationInput(from_hex(payload["public_value"]), context, parse_proof(payload["proof"]))


def read_json(path: Path, max_bytes: int = MAX_BODY_BYTES) -> object:
    with path.open("rb") as file:
        payload = file.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"JSON input exceeds {max_bytes} bytes.")
    try:
        return json.loads(payload.decode("utf-8"))
    except (ValueError, RecursionError):
        raise ValueError("Expected valid UTF-8 JSON.") from None


def save_proof(path: Path, proof: Proof) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file = NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False)
    temporary = Path(file.name)
    try:
        with file:
            json.dump(proof_payload(proof), file, indent=2)
            file.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)

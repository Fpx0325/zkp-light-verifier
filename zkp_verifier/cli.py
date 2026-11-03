"""Generate proofs locally, verify them, and inspect the audit database."""

import argparse
import json
import sqlite3
import sys
import warnings
from dataclasses import asdict, replace
from getpass import GetPassWarning, getpass
from pathlib import Path

from .audit import AuditLog
from .config import MAX_BATCH_SIZE, MAX_LOG_PAGE, log_path
from .core.number_theory import Q, context_bytes
from .core.proof_build import create_proof
from .core.secret_gen import generate_secret
from .core.verify_logic import VerificationInput
from .proof_io import MAX_PROOF_BYTES, from_hex, parse_item, parse_proof, read_json, save_proof, to_hex
from .service import RunResult, verify_batch

DEFAULT_PROOF = Path("data/proof.json")


def read_secret() -> int:
    if not sys.stdin.isatty():
        raise ValueError("Enter your secret from an interactive terminal.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        try:
            return int(getpass("Secret integer (hidden): "))
        except ValueError:
            raise ValueError("Secret must be a decimal integer.") from None
        except GetPassWarning:
            raise ValueError("This terminal cannot hide the input.") from None


def open_audit(args: argparse.Namespace) -> AuditLog:
    audit = AuditLog(args.log_db)
    audit.initialize()
    return audit


def check_paths(proof_path: Path, database_path: Path) -> None:
    if proof_path.resolve() == database_path.resolve():
        raise ValueError("Use separate paths for the proof input or output and the audit database.")


def print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def print_verification(result: RunResult) -> int:
    print_json(asdict(result))
    return 0 if all(check.accepted for check in result.results) else 1


def run_demo(args: argparse.Namespace) -> int:
    context = "classroom-demo"
    public_value, proof = create_proof(generate_secret(), context)
    tampered = replace(proof, response=(proof.response + 1) % Q)
    result = verify_batch(open_audit(args), "demo", [
        VerificationInput(public_value, context, proof),
        VerificationInput(public_value, context, tampered),
    ])
    print_json(asdict(result))
    return 0 if [check.accepted for check in result.results] == [True, False] else 1


def run_prove(args: argparse.Namespace) -> int:
    check_paths(args.out, args.log_db)
    context_bytes(args.context)
    secret = read_secret() if args.prompt_secret else generate_secret()
    public_value, proof = create_proof(secret, args.context)
    save_proof(args.out, proof)
    print(to_hex(public_value))
    return 0


def run_verify(args: argparse.Namespace) -> int:
    check_paths(args.proof, args.log_db)
    context_bytes(args.context)
    proof = parse_proof(read_json(args.proof, MAX_PROOF_BYTES))
    item = VerificationInput(from_hex(args.public_value), args.context, proof)
    return print_verification(verify_batch(open_audit(args), "cli", [item]))


def run_batch(args: argparse.Namespace) -> int:
    check_paths(args.batch, args.log_db)
    payload = read_json(args.batch)
    if not isinstance(payload, dict) or payload.keys() != {"items"}:
        raise ValueError("Batch input must be a JSON object with an items array.")
    items = payload["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH_SIZE:
        raise ValueError(f"Batch input must contain 1 to {MAX_BATCH_SIZE} items.")
    inputs = [parse_item(item) for item in items]
    return print_verification(verify_batch(open_audit(args), "cli", inputs))


def run_logs(args: argparse.Namespace) -> int:
    if not 1 <= args.limit <= MAX_LOG_PAGE:
        raise ValueError(f"Limit must be between 1 and {MAX_LOG_PAGE}.")
    if args.before_id is not None and not 1 <= args.before_id <= 2**63 - 1:
        raise ValueError("before-id must be a positive SQLite integer.")
    entries = open_audit(args).recent(args.limit, args.before_id)
    print_json([asdict(entry) for entry in entries])
    return 0


def run_stats(args: argparse.Namespace) -> int:
    print_json({group: asdict(counts) for group, counts in open_audit(args).stats().items()})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lightweight Schnorr zero-knowledge proof verifier.")
    parser.add_argument("--log-db", type=Path, default=log_path(), help="Path to the SQLite audit database.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Verify an original and tampered proof.").set_defaults(run=run_demo)

    prove = commands.add_parser("prove", help="Save a proof and print its public value.")
    prove.add_argument("--context", required=True)
    prove.add_argument("--out", type=Path, default=DEFAULT_PROOF)
    prove.add_argument("--prompt-secret", action="store_true")
    prove.set_defaults(run=run_prove)

    verify = commands.add_parser("verify", help="Verify a proof with the expected public value and context.")
    verify.add_argument("proof", type=Path)
    verify.add_argument("--public-value", required=True)
    verify.add_argument("--context", required=True)
    verify.set_defaults(run=run_verify)

    batch = commands.add_parser("verify-batch", help="Verify a JSON batch and record a single run.")
    batch.add_argument("batch", type=Path)
    batch.set_defaults(run=run_batch)

    logs = commands.add_parser("logs", help="Read recent audit records, newest first.")
    logs.add_argument("--limit", type=int, default=20)
    logs.add_argument("--before-id", type=int)
    logs.set_defaults(run=run_logs)

    commands.add_parser("stats", help="Show verification and demo totals.").set_defaults(run=run_stats)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (OSError, EOFError, ValueError, sqlite3.Error) as error:
        parser.exit(2, f"Error: {error}\n")

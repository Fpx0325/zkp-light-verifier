import json
import sqlite3
import subprocess
import sys
import unittest
from contextlib import AsyncExitStack, closing
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from httpx import ASGITransport, AsyncClient

from zkp_verifier.api.app import create_app
from zkp_verifier.audit import AuditLog
from zkp_verifier.config import MAX_BATCH_SIZE, MAX_BODY_BYTES
from zkp_verifier.core.number_theory import P, Q
from zkp_verifier.core.proof_build import create_proof
from zkp_verifier.core.secret_gen import derive_public_value, generate_secret
from zkp_verifier.core.verify_logic import Verdict, VerificationInput, verify
from zkp_verifier.proof_io import proof_payload, to_hex


class ProofTests(unittest.TestCase):
    def test_expected_value_and_context(self):
        secret = generate_secret()
        public_value, proof = create_proof(secret, "lesson")
        item = VerificationInput(public_value, "lesson", proof)
        other_value = derive_public_value(secret % (Q - 1) + 1)
        self.assertEqual(verify(item), Verdict.VERIFIED)
        self.assertEqual(verify(replace(item, context="other")), Verdict.EQUATION_MISMATCH)
        self.assertEqual(verify(replace(item, public_value=other_value)), Verdict.EQUATION_MISMATCH)

    def test_invalid_group_inputs(self):
        public_value, proof = create_proof(generate_secret(), "lesson")
        item = VerificationInput(public_value, "lesson", proof)
        self.assertEqual(verify(replace(item, public_value=P - 1)), Verdict.INVALID_PUBLIC_VALUE)
        self.assertEqual(verify(replace(item, proof=replace(proof, commitment=1))), Verdict.INVALID_COMMITMENT)
        self.assertEqual(verify(replace(item, proof=replace(proof, response=Q))), Verdict.INVALID_RESPONSE)


class AuditTests(unittest.TestCase):
    def test_failed_batch_write_rolls_back_run_and_checks(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            audit = AuditLog(path)
            audit.initialize()
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("""
                    CREATE TRIGGER fail_second_check BEFORE INSERT ON audit_checks
                    WHEN NEW.position = 2 BEGIN SELECT RAISE(ABORT, 'test error'); END
                """)
            with self.assertRaises(sqlite3.IntegrityError):
                audit.append("test-run", "2026-01-01T00:00:00+00:00", "api", [Verdict.VERIFIED] * 2)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_runs").fetchone(), (0,))
            self.assertEqual(audit.recent(20), [])


class ApiTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        public_value, proof = create_proof(generate_secret(), "lesson")
        cls.item = {"public_value": to_hex(public_value), "context": "lesson", "proof": proof_payload(proof)}

    async def asyncSetUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        app = create_app(Path(temporary.name) / "api.sqlite3")
        stack = AsyncExitStack()
        self.addAsyncCleanup(stack.aclose)
        await stack.enter_async_context(app.router.lifespan_context(app))
        self.client = await stack.enter_async_context(AsyncClient(
            transport=ASGITransport(app=app), base_url="http://testserver",
        ))

    async def test_public_routes_batch_stats_and_pagination(self):
        self.assertEqual((await self.client.get("/health")).json(), {"status": "ok"})
        self.assertEqual((await self.client.get("/docs")).status_code, 200)
        valid = await self.client.post("/v1/verify", json=self.item)
        self.assertEqual(valid.status_code, 200)
        self.assertTrue(valid.json()["results"][0]["accepted"])
        response = await self.client.post(
            "/v1/verify/batch", json={"items": [self.item, self.item | {"context": "wrong"}]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual([check["accepted"] for check in response.json()["results"]], [True, False])
        first_page = (await self.client.get("/v1/logs", params={"limit": 1})).json()
        self.assertEqual(first_page[0]["run_id"], response.json()["run_id"])
        self.assertEqual(set(first_page[0]), {"id", "run_id", "source", "position", "checked_at_utc", "verdict"})
        next_page = (await self.client.get("/v1/logs", params={"before_id": first_page[0]["id"]})).json()
        self.assertEqual(len(next_page), 2)
        stats = (await self.client.get("/v1/stats")).json()
        self.assertEqual(stats["verification"], {"total": 3, "accepted": 2, "rejected": 1, "acceptance_rate": 2 / 3})
        self.assertIsNone(stats["demo"]["acceptance_rate"])

    async def test_reject_invalid_batch_without_logging_or_echoing_input(self):
        invalid = self.item | {"secret": "example-private-input"}
        response = await self.client.post("/v1/verify/batch", json={"items": [self.item, invalid]})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("example-private-input", response.text)
        self.assertEqual((await self.client.get("/v1/logs")).json(), [])
        response = await self.client.post(
            "/v1/verify/batch", json={"items": [self.item] * (MAX_BATCH_SIZE + 1)},
        )
        self.assertEqual(response.status_code, 422)

    async def test_request_size_and_utf8_context_limits(self):
        async def chunks():
            yield b" " * MAX_BODY_BYTES
            yield b"{}"

        response = await self.client.post(
            "/v1/verify",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)
        response = await self.client.post("/v1/verify", json=self.item | {"context": "场" * 86})
        self.assertEqual(response.status_code, 422)
        self.assertEqual((await self.client.get("/v1/logs")).json(), [])


class CliTests(unittest.TestCase):
    def test_prove_verify_batch_and_separate_demo_statistics(self):
        entry = Path(__file__).resolve().parents[1] / "main.py"
        with TemporaryDirectory() as directory:
            def run(*args, status=0):
                result = subprocess.run(
                    [sys.executable, str(entry), *args],
                    cwd=directory, capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, status, result.stderr or result.stdout)
                return result.stdout

            public_value = run("prove", "--context", "lesson").strip()
            run("verify", "data/proof.json", "--public-value", public_value, "--context", "lesson")
            proof = json.loads((Path(directory) / "data/proof.json").read_text(encoding="utf-8"))
            item = {"public_value": public_value, "context": "wrong", "proof": proof}
            (Path(directory) / "batch.json").write_text(json.dumps({"items": [item]}), encoding="utf-8")
            run("verify-batch", "batch.json", status=1)
            run("demo")
            stats = json.loads(run("stats"))
            for kind in ("demo", "verification"):
                self.assertEqual(stats[kind], {"total": 2, "accepted": 1, "rejected": 1, "acceptance_rate": 0.5})


if __name__ == "__main__":
    unittest.main()

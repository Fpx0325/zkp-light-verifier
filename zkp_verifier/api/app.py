"""FastAPI application for verification, audit queries and statistics."""

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..audit import AuditLog, LogEntry, Totals
from ..config import MAX_BODY_BYTES, MAX_LOG_PAGE, log_path
from ..service import RunResult, verify_batch
from .schemas import BatchBody, VerificationBody


class LimitRequestBody:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return

        size = 0

        async def bounded_receive() -> Message:
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > MAX_BODY_BYTES:
                    raise HTTPException(413, "Request body exceeds 128 KiB.")
            return message

        await self.app(scope, bounded_receive, send)


def create_app(database: Path | None = None) -> FastAPI:
    audit = AuditLog(database if database is not None else log_path())

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        audit.initialize()
        yield

    application = FastAPI(title="轻量化零知识证明验证系统", version="1.0.0", lifespan=lifespan)
    application.add_middleware(LimitRequestBody)

    @application.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid input. See /docs for the request schema."}, status_code=422)

    @application.exception_handler(sqlite3.Error)
    async def storage_unavailable(_: Request, __: sqlite3.Error) -> JSONResponse:
        return JSONResponse({"detail": "Audit storage is unavailable."}, status_code=503)

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.post("/v1/verify")
    def verify_one(body: VerificationBody) -> RunResult:
        return verify_batch(audit, "api", [body.to_input()])

    @application.post("/v1/verify/batch")
    def verify_many(body: BatchBody) -> RunResult:
        return verify_batch(audit, "api", [item.to_input() for item in body.items])

    @application.get("/v1/logs")
    def logs(
        limit: Annotated[int, Query(ge=1, le=MAX_LOG_PAGE)] = 20,
        before_id: Annotated[int | None, Query(ge=1, le=2**63 - 1)] = None,
    ) -> list[LogEntry]:
        return audit.recent(limit, before_id)

    @application.get("/v1/stats")
    def stats() -> dict[str, Totals]:
        return audit.stats()

    return application


app = create_app()

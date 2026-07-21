"""FastAPI application factory.

Wires CORS (two-origin web↔api topology), a request-id middleware so every response
is traceable, typed/display-safe error handling, and the API routers. Tables are
created on startup for the SQLite demo (Alembic owns schema evolution in deployment).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.db.base import init_db
from app.domain.lifecycle import LifecycleError
from app.routers import delegations, evidence, lifecycle, operator, security, system
from app.schemas.common import ErrorBody, ErrorResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create demo tables on startup."""
    init_db()
    yield


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = get_settings()
    app = FastAPI(title="SafeDelegate Trace API", version="0.1.0", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_request_id(
        request: Request, call_next: Callable[[Request], Awaitable[JSONResponse]]
    ) -> JSONResponse:
        """Attach a unique request_id to every request and echo it in a header."""
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Return a typed, display-safe error body for HTTP errors."""
        request_id = getattr(request.state, "request_id", "unknown")
        body = ErrorResponse(
            request_id=request_id,
            error=ErrorBody(code=f"http_{exc.status_code}", message=str(exc.detail)),
        )
        return JSONResponse(status_code=exc.status_code, content=body.model_dump())

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Surface request validation failures without leaking internals."""
        request_id = getattr(request.state, "request_id", "unknown")
        body = ErrorResponse(
            request_id=request_id,
            error=ErrorBody(
                code="validation_error",
                message="Request payload failed validation.",
                details={"errors": exc.errors()},
            ),
        )
        return JSONResponse(status_code=422, content=body.model_dump())

    @app.exception_handler(LifecycleError)
    async def lifecycle_exception_handler(
        request: Request, exc: LifecycleError
    ) -> JSONResponse:
        """Map lifecycle/state-machine violations to typed, display-safe errors."""
        request_id = getattr(request.state, "request_id", "unknown")
        body = ErrorResponse(
            request_id=request_id,
            error=ErrorBody(code=exc.code, message=exc.message),
        )
        return JSONResponse(status_code=exc.status_code, content=body.model_dump())

    app.include_router(system.router)
    app.include_router(delegations.router)
    app.include_router(lifecycle.router)
    app.include_router(evidence.router)
    app.include_router(security.router)
    app.include_router(operator.router)
    return app


app = create_app()

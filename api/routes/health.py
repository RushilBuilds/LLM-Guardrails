"""Health-check endpoint."""

from fastapi import APIRouter

from api.schemas import HealthResponse
import guardrails

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health() -> HealthResponse:
    """Returns service status and library version."""
    return HealthResponse(status="ok", version=guardrails.__version__)

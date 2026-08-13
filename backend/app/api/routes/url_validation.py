from typing import Annotated

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.security.url_validator import UrlValidationError, validate_public_url


router = APIRouter(prefix="/api/url-validation", tags=["url-validation"])


class UrlValidationRequest(BaseModel):
    url: Annotated[str, Field(max_length=2_048)]


class UrlValidationResponse(BaseModel):
    valid: bool
    normalized_url: str
    hostname: str


@router.post("", response_model=UrlValidationResponse)
def validate_url(request: UrlValidationRequest) -> UrlValidationResponse:
    try:
        validated = validate_public_url(request.url)
    except UrlValidationError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": error.code, "message": error.message},
        ) from error

    return UrlValidationResponse(
        valid=True,
        normalized_url=validated.normalized_url,
        hostname=validated.hostname,
    )

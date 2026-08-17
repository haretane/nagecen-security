import uuid

import pytest
from pydantic import ValidationError

from app.api.routes.scan_jobs import ScanJobCreateRequest


def valid_request_data() -> dict:
    return {
        "verified_target_id": uuid.uuid4(),
        "level_id": "basic",
        "authorization_confirmed": True,
        "active_scan_confirmed": False,
        "data_change_risk_acknowledged": False,
        "authentication_type": "none",
        "service_features": ["view_only"],
    }


@pytest.mark.parametrize("authentication_type", ["none", "form", "external", "special"])
def test_authentication_questionnaire_accepts_supported_choices(authentication_type: str) -> None:
    request_data = valid_request_data()
    request_data["authentication_type"] = authentication_type
    if authentication_type == "form":
        request_data["form_authentication"] = {
            "login_url": "https://example.com/login",
            "identifier": "diagnosis-user@example.com",
            "password": "temporary-secret",
        }

    request = ScanJobCreateRequest.model_validate(request_data)

    assert request.authentication_type == authentication_type


def test_authentication_questionnaire_rejects_unknown_choice() -> None:
    request_data = valid_request_data()
    request_data["authentication_type"] = "social-login"

    with pytest.raises(ValidationError):
        ScanJobCreateRequest.model_validate(request_data)


def test_scan_request_rejects_password_field() -> None:
    request_data = valid_request_data()
    request_data["password"] = "must-not-be-accepted-here"

    with pytest.raises(ValidationError):
        ScanJobCreateRequest.model_validate(request_data)


def test_form_authentication_requires_details() -> None:
    request_data = valid_request_data()
    request_data["authentication_type"] = "form"

    with pytest.raises(ValidationError):
        ScanJobCreateRequest.model_validate(request_data)


def test_password_is_masked_in_model_representation() -> None:
    request_data = valid_request_data()
    request_data["authentication_type"] = "form"
    request_data["form_authentication"] = {
        "login_url": "https://example.com/login",
        "identifier": "diagnosis-user@example.com",
        "password": "must-not-appear-in-repr",
    }

    request = ScanJobCreateRequest.model_validate(request_data)

    assert "must-not-appear-in-repr" not in repr(request)


def test_unknown_service_feature_must_be_selected_alone() -> None:
    request_data = valid_request_data()
    request_data["service_features"] = ["unknown", "login"]

    with pytest.raises(ValidationError):
        ScanJobCreateRequest.model_validate(request_data)

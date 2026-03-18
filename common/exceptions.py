"""
Custom exception handling for DjangoAuth API.

Registered in settings/base.py as:
    REST_FRAMEWORK["EXCEPTION_HANDLER"] = "common.exceptions.custom_exception_handler"

All unhandled DRF exceptions are caught here and converted into the
standard error envelope.
"""

import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Call DRF's default handler first, then re-wrap the response
    into our standard error envelope. Includes passthrough for AppBaseException.
    """
    response = exception_handler(exc, context)

    # 1. Handle our custom application exceptions
    if isinstance(exc, AppBaseException):
        return Response(
            {
                "success": False,
                "message": exc.message,
                "errors": {},
            },
            status=exc.status_code,
        )

    # 2. Handle DRF exceptions (Validation, Authentication, etc.)
    if response is not None:
        detail = response.data

        if isinstance(detail, dict) and "detail" in detail:
            message = str(detail["detail"])
            errors = {}
        elif isinstance(detail, dict):
            message = "Validation failed"
            errors = detail
        elif isinstance(detail, list):
            message = "Validation failed"
            errors = {"non_field_errors": detail}
        else:
            message = str(detail)
            errors = {}

        response.data = {
            "success": False,
            "message": message,
            "errors": errors,
        }
        return response

    # 3. Unhandled unexpected exceptions (Code bugs, Server issues)
    logger.exception("Unhandled exception: %s", exc)
    return Response(
        {
            "success": False,
            "message": "An unexpected error occurred. Please try again later.",
            "errors": {},
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


# ---------------------------------------------------------------------------
# Custom application exceptions
# ---------------------------------------------------------------------------


class AppBaseException(Exception):
    """Base class for all application-level exceptions."""

    default_message = "An application error occurred."
    default_status = status.HTTP_400_BAD_REQUEST

    def __init__(self, message=None, status_code=None):
        self.message = message or self.default_message
        self.status_code = status_code or self.default_status
        super().__init__(self.message)


class ConfigNotFoundException(AppBaseException):
    default_message = "Configuration key not found."
    default_status = status.HTTP_404_NOT_FOUND


class FeatureDisabledException(AppBaseException):
    default_message = "This feature is currently disabled."
    default_status = status.HTTP_403_FORBIDDEN


class AccountLockedException(AppBaseException):
    default_message = "Account is temporarily locked due to too many failed attempts."
    default_status = status.HTTP_403_FORBIDDEN


class OTPExpiredException(AppBaseException):
    default_message = "OTP has expired. Please request a new one."
    default_status = status.HTTP_400_BAD_REQUEST


class OTPInvalidException(AppBaseException):
    default_message = "Invalid OTP code."
    default_status = status.HTTP_400_BAD_REQUEST


class PasswordPolicyViolationException(AppBaseException):
    default_message = "Password does not meet the required policy."
    default_status = status.HTTP_400_BAD_REQUEST


class PasswordReuseException(AppBaseException):
    default_message = "You cannot reuse a recent password."
    default_status = status.HTTP_400_BAD_REQUEST


class InvalidCredentialsException(AppBaseException):
    default_message = "Invalid email or password."
    default_status = status.HTTP_401_UNAUTHORIZED


class RegistrationException(AppBaseException):
    default_message = "Registration failed."
    default_status = status.HTTP_400_BAD_REQUEST


class SessionRevokedException(AppBaseException):
    default_message = "Session has been revoked."
    default_status = status.HTTP_401_UNAUTHORIZED

"""
Standard API response builder.

Every view must return responses through these helpers so that the
envelope shape is always consistent:

    Success: {"success": true,  "message": "...", "data": {...}}
    Error:   {"success": false, "message": "...", "errors": {...}}
"""

from rest_framework.response import Response
from rest_framework import status


def success_response(
    message: str = "Request successful",
    data=None,
    status_code: int = status.HTTP_200_OK,
) -> Response:
    """Return a standardised success envelope."""
    payload = {
        "success": True,
        "message": message,
        "data": data if data is not None else {},
    }
    return Response(payload, status=status_code)


def created_response(
    message: str = "Resource created successfully",
    data=None,
) -> Response:
    """Convenience wrapper for 201 Created."""
    return success_response(message=message, data=data, status_code=status.HTTP_201_CREATED)


def error_response(
    message: str = "An error occurred",
    errors=None,
    status_code: int = status.HTTP_400_BAD_REQUEST,
) -> Response:
    """Return a standardised error envelope."""
    payload = {
        "success": False,
        "message": message,
        "errors": errors if errors is not None else {},
    }
    return Response(payload, status=status_code)


def not_found_response(message: str = "Resource not found") -> Response:
    return error_response(message=message, status_code=status.HTTP_404_NOT_FOUND)


def unauthorized_response(message: str = "Authentication required") -> Response:
    return error_response(message=message, status_code=status.HTTP_401_UNAUTHORIZED)


def forbidden_response(message: str = "You do not have permission to perform this action") -> Response:
    return error_response(message=message, status_code=status.HTTP_403_FORBIDDEN)


def server_error_response(message: str = "Internal server error") -> Response:
    return error_response(message=message, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

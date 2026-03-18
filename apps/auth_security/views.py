"""
auth_security API views.

Rules:
- Views only handle HTTP: parse requests, call services, return standard responses.
- No direct model access in views (calls AuthService, OTPService, etc.).
- All write operations trigger audit logging within the services.
- Versioned endpoints (v1).
"""

from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView
from drf_spectacular.utils import extend_schema

from apps.auth_security.services.auth_service import AuthService
from apps.auth_security.services.otp_service import OTPService
from apps.auth_security.services.password_service import PasswordService
from apps.auth_security.services.session_service import SessionService
from apps.auth_security.serializers import (
    RegisterSerializer,
    LoginSerializer,
    OTPSendSerializer,
    OTPVerifySerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    AuthUserSerializer,
    AuthUserProfileSerializer,
    AuthSessionLogSerializer,
)
from apps.auth_security.throttles import LoginRateThrottle, OTPSendRateThrottle, PasswordResetRateThrottle
from apps.auth_security.constants import OTPPurpose
from common.response import success_response, created_response, error_response


# ---------------------------------------------------------------------------
# Registration & Login
# ---------------------------------------------------------------------------

class RegisterAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    @extend_schema(responses={201: AuthUserSerializer})
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = AuthService().register(
            email=serializer.validated_data["email"],
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT")
        )

        return created_response(
            message="User registered successfully.",
            data=AuthUserSerializer(user).data
        )


class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    # Throttle is applied per DRF scope, here we use our custom throttle class
    throttle_classes = [LoginRateThrottle]
    serializer_class = LoginSerializer

    @extend_schema(responses={200: AuthUserSerializer})
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = AuthService().login(
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT")
        )

        return success_response(
            message="Login successful.",
            data={
                "access": result["access"],
                "refresh": result["refresh"],
                "user": AuthUserSerializer(result["user"]).data
            }
        )


class LogoutAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        # In simplejwt, access token JTI is usually in the request.auth token object 
        # if using JWTAuthentication
        session_key = str(request.auth.get("jti")) if request.auth else None

        AuthService().logout(
            user=request.user,
            session_key=session_key,
            raw_refresh_token=refresh_token,
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT")
        )

        return success_response(message="Logged out successfully.")


class TokenRefreshAPIView(BaseTokenRefreshView):
    """Simple wrapper over SimpleJWT's TokenRefreshView to ensure docs are generated."""
    @extend_schema(responses={200: {"access": "string"}})
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


# ---------------------------------------------------------------------------
# OTP Verification
# ---------------------------------------------------------------------------

class OTPSendAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    # Limit requests per IP/user
    throttle_classes = [OTPSendRateThrottle]
    serializer_class = OTPSendSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.filter(email=serializer.validated_data["email"]).first()

        # Security: Don't leak whether user exists. Always return 200.
        if user:
            OTPService().send_otp(user=user, purpose=serializer.validated_data["purpose"])

        return success_response(message="If a matching account exists, an OTP has been sent.")


class OTPVerifyAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = OTPVerifySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.filter(email=serializer.validated_data["email"]).first()

        if user:
            OTPService().verify_otp(
                user=user,
                otp_code=serializer.validated_data["otp_code"],
                purpose=serializer.validated_data["purpose"]
            )
            return success_response(message="OTP verified successfully.")

        return error_response(message="Invalid or expired OTP code.", status_code=status.HTTP_400_BAD_REQUEST)


# ---------------------------------------------------------------------------
# Password Management
# ---------------------------------------------------------------------------

class PasswordChangeAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        PasswordService().change_password(
            user=request.user,
            old_password=serializer.validated_data["old_password"],
            new_password=serializer.validated_data["new_password"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT")
        )

        return success_response(message="Password changed successfully.")


class PasswordResetRequestAPIView(APIView):
    """Step 1 — Request password reset OTP."""
    permission_classes = [permissions.AllowAny]
    # Limit requests to prevent spamming passwords reset requests
    throttle_classes = [PasswordResetRateThrottle]
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.filter(email=serializer.validated_data["email"]).first()

        # Security: Don't leak email existence
        if user:
            OTPService().send_otp(user=user, purpose=OTPPurpose.PASSWORD_RESET)

        return success_response(message="If a matching account exists, a reset code has been sent.")


class PasswordResetConfirmAPIView(APIView):
    """Step 2 — Confirm password reset with OTP."""
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.filter(email=serializer.validated_data["email"]).first()

        if not user:
            return error_response(message="Invalid email or code.", status_code=status.HTTP_400_BAD_REQUEST)

        # 1. Verify OTP
        OTPService().verify_otp(
            user=user,
            otp_code=serializer.validated_data["otp_code"],
            purpose=OTPPurpose.PASSWORD_RESET
        )

        # 2. Update password
        PasswordService().reset_password(
            user=user,
            new_password=serializer.validated_data["new_password"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT")
        )

        return success_response(message="Password reset successfully. Please login with your new password.")


# ---------------------------------------------------------------------------
# Sessions & Profile
# ---------------------------------------------------------------------------

class UserProfileAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AuthUserProfileSerializer

    @extend_schema(responses={200: AuthUserSerializer})
    def get(self, request):
        # Full user data including profile
        return success_response(data=AuthUserSerializer(request.user).data)

    def patch(self, request):
        serializer = self.serializer_class(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        profile = AuthService().update_profile(user=request.user, **serializer.validated_data)
        return success_response(
            message="Profile updated successfully.",
            data=AuthUserProfileSerializer(profile).data
        )


class SessionListAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: AuthSessionLogSerializer(many=True)})
    def get(self, request):
        sessions = SessionService().get_active_sessions(user=request.user)
        return success_response(data=AuthSessionLogSerializer(sessions, many=True).data)


class SessionRevokeAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        revoked = SessionService().revoke_by_id(session_id=pk, user=request.user)
        if not revoked:
            return error_response(message="Session not found or already inactive.", status_code=status.HTTP_404_NOT_FOUND)

        return success_response(message="Session revoked successfully.")

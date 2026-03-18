"""
auth_security URL configuration.

All endpoints are prefixed with /api/v1/auth/ (via root urls.py).
Follows RESTful principles and versioning scheme.
"""

from django.urls import path
from . import views

app_name = "auth_security"

urlpatterns = [
    # Registration & Login
    path("register/", views.RegisterAPIView.as_view(), name="register"),
    path("login/", views.LoginAPIView.as_view(), name="login"),
    path("logout/", views.LogoutAPIView.as_view(), name="logout"),
    path("token/refresh/", views.TokenRefreshAPIView.as_view(), name="token_refresh"),

    # OTP
    path("otp/send/", views.OTPSendAPIView.as_view(), name="otp_send"),
    path("otp/verify/", views.OTPVerifyAPIView.as_view(), name="otp_verify"),

    # Password Management
    path("password/change/", views.PasswordChangeAPIView.as_view(), name="password_change"),
    path("password/reset/", views.PasswordResetRequestAPIView.as_view(), name="password_reset_request"),
    path("password/reset/confirm/", views.PasswordResetConfirmAPIView.as_view(), name="password_reset_confirm"),

    # Profile & Sessions
    path("profile/", views.UserProfileAPIView.as_view(), name="profile"),
    path("sessions/", views.SessionListAPIView.as_view(), name="session_list"),
    path("sessions/<int:pk>/", views.SessionRevokeAPIView.as_view(), name="session_revoke"),
]

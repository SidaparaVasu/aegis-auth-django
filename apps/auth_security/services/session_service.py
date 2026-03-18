"""
SessionService — JWT issuance and session lifecycle management.

Rules:
    - A new AuthSessionLog is created on EVERY successful login.
    - session_key stores the JWT JTI (unique per token).
    - Sessions are soft-revoked (is_active=False) on logout.
    - Refresh tokens are blacklisted via simplejwt token_blacklist.
"""

import logging

logger = logging.getLogger(__name__)


class SessionService:

    def __init__(self, session_repo=None, audit_service=None):
        self._session_repo = session_repo
        self._audit_service = audit_service

    @property
    def session_repo(self):
        if self._session_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthSessionRepository
            self._session_repo = AuthSessionRepository()
        return self._session_repo

    @property
    def audit_service(self):
        if self._audit_service is None:
            from apps.core_system.services.audit_service import AuditService
            self._audit_service = AuditService()
        return self._audit_service

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(
        self,
        user,
        ip_address: str,
        user_agent: str | None = None,
    ) -> tuple[str, str, str]:
        """
        Issue a JWT pair and create an AuthSessionLog record.

        Returns:
            (access_token_str, refresh_token_str, session_key)

        The session_key is the JWT JTI claim and uniquely identifies this session.
        """
        from rest_framework_simplejwt.tokens import RefreshToken

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        session_key = str(access["jti"])

        self.session_repo.create(
            user=user,
            session_key=session_key,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info("Session created: user_id=%s session_key=%s", user.id, session_key[:8] + "…")
        return str(access), str(refresh), session_key

    def revoke_by_key(self, session_key: str) -> bool:
        """
        Soft-revoke a session by its JTI key (used on logout).
        Returns True if a session record was updated.
        """
        revoked = self.session_repo.revoke_by_key(session_key)
        if revoked:
            logger.info("Session revoked by key: %s…", session_key[:8])
        return revoked

    def revoke_by_id(self, session_id: int, user) -> bool:
        """
        Revoke a specific session by its PK (session management endpoint).
        Ensures the session belongs to the requesting user.
        Returns True if revoked.
        """
        revoked = self.session_repo.revoke_by_id(session_id, user)
        if revoked:
            logger.info("Session %s revoked by user_id=%s", session_id, user.id)
        return revoked

    def revoke_all_sessions(self, user) -> int:
        """Revoke ALL active sessions for a user (e.g. on password reset)."""
        count = self.session_repo.revoke_all_for_user(user)
        logger.info("All %d sessions revoked for user_id=%s", count, user.id)
        return count

    def get_active_sessions(self, user) -> list:
        """Return all active AuthSessionLog records for a user."""
        return self.session_repo.get_active_for_user(user)

    @staticmethod
    def blacklist_refresh_token(raw_refresh: str) -> bool:
        """
        Add a refresh token to the simplejwt blacklist.
        Returns True on success, False if token is invalid or already blacklisted.
        """
        try:
            from rest_framework_simplejwt.tokens import RefreshToken
            token = RefreshToken(raw_refresh)
            token.blacklist()
            return True
        except Exception as exc:
            logger.warning("Failed to blacklist refresh token: %s", exc)
            return False

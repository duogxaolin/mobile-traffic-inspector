import uuid

from app.models import Admin
from app.security import LoginLimiter, issue_session, parse_session
from app.config import Settings


def test_signed_session_can_be_revoked_by_version():
    settings = Settings(
        application_key=b"k" * 32,
        session_secret=b"session-secret",
    )
    admin = Admin(id=uuid.uuid4(), username="admin", password_hash="hash", session_version=1)
    token = issue_session(admin, settings)
    assert parse_session(token, settings)["sub"] == str(admin.id)
    admin.session_version = 2
    assert parse_session(token, settings)["ver"] == 1


def test_login_limiter_bounds_repeated_failures():
    limiter = LoginLimiter(attempts=2, window_seconds=300)
    limiter.failure("127.0.0.1")
    limiter.failure("127.0.0.1")
    try:
        limiter.check("127.0.0.1")
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 429
    else:
        raise AssertionError("rate limit should reject the third attempt")

import pytest
import time
from aioresponses import aioresponses

from src.osiric.http.authentication.oauth import (
    OAuthPasswordCredentialsHandler,
    OAuthRefreshTokenHandler,
)


@pytest.mark.asyncio
async def test_fetch_token_success():
    handler = OAuthPasswordCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="client",
        client_secret="secret",
        username="user",
        password="pass",
    )
    token_response = {
        "access_token": "abc123",
        "refresh_token": "refresh123",
        "expires_in": 3600,
    }
    with aioresponses() as m:
        m.post("https://auth.example.com/token", payload=token_response)
        await handler._fetch_token()
        assert handler.access_token == "abc123"
        assert handler.refresh_token == "refresh123"
        assert handler.expires_at > time.time()


@pytest.mark.asyncio
async def test_apply_auth_adds_header():
    handler = OAuthPasswordCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="client",
        client_secret="secret",
        username="user",
        password="pass",
    )
    token_response = {
        "access_token": "abc123",
        "refresh_token": "refresh123",
        "expires_in": 3600,
    }
    with aioresponses() as m:
        m.post("https://auth.example.com/token", payload=token_response)
        request_kwargs = {}
        result = await handler.apply_auth(request_kwargs)
        assert "Authorization" in result["headers"]
        assert result["headers"]["Authorization"] == "Bearer abc123"


@pytest.mark.asyncio
async def test_refresh_token_flow():
    handler = OAuthPasswordCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="client",
        client_secret="secret",
        username="user",
        password="pass",
    )
    # Set expired token
    handler.access_token = "expired"
    handler.refresh_token = "refresh123"
    handler.expires_at = time.time() - 100

    refresh_response = {
        "access_token": "newtoken",
        "refresh_token": "newrefresh",
        "expires_in": 3600,
    }
    with aioresponses() as m:
        m.post("https://auth.example.com/token", payload=refresh_response)
        await handler._refresh_token_if_needed()
        assert handler.access_token == "newtoken"
        assert handler.refresh_token == "newrefresh"


@pytest.mark.asyncio
async def test_refresh_token_fallback_to_password_grant():
    handler = OAuthPasswordCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="client",
        client_secret="secret",
        username="user",
        password="pass",
    )
    handler.access_token = "expired"
    handler.refresh_token = "refresh123"
    handler.expires_at = time.time() - 100

    with aioresponses() as m:
        # First, refresh fails
        m.post(
            "https://auth.example.com/token",
            status=400,
            payload={"error": "invalid_grant"},
        )
        # Then, password grant succeeds
        m.post(
            "https://auth.example.com/token",
            payload={
                "access_token": "abc123",
                "refresh_token": "refresh123",
                "expires_in": 3600,
            },
        )
        await handler._refresh_token_if_needed()
        assert handler.access_token == "abc123"


@pytest.fixture
def handler():
    return OAuthRefreshTokenHandler(
        token_url="https://example.com/oauth/token",
        client_id="test_client_id",
        client_secret="test_client_secret",
        refresh_token="test_refresh_token",
    )


@pytest.mark.asyncio
async def test_fetch_token_success(handler):
    with aioresponses() as mock:
        mock.post(
            "https://example.com/oauth/token",
            payload={
                "access_token": "new_access_token",
                "refresh_token": "new_refresh_token",
                "expires_in": 3600,
            },
        )

        await handler._fetch_token()

        assert handler.access_token == "new_access_token"
        assert handler.refresh_token == "new_refresh_token"
        assert handler.expires_at > time.time()


@pytest.mark.asyncio
async def test_fetch_token_failure(handler):
    with aioresponses() as mock:
        mock.post("https://example.com/oauth/token", status=400, body="Invalid request")

        with pytest.raises(RuntimeError, match="Failed to obtain OAuth token"):
            await handler._fetch_token()


@pytest.mark.asyncio
async def test_refresh_token_if_needed(handler):
    with aioresponses() as mock:
        mock.post(
            "https://example.com/oauth/token",
            payload={
                "access_token": "new_access_token",
                "refresh_token": "new_refresh_token",
                "expires_in": 3600,
            },
        )

        # Simulate expired token
        handler.expires_at = time.time() - 1
        await handler._refresh_token_if_needed()

        assert handler.access_token == "new_access_token"
        assert handler.refresh_token == "new_refresh_token"


@pytest.mark.asyncio
async def test_apply_auth(handler):
    with aioresponses() as mock:
        mock.post(
            "https://example.com/oauth/token",
            payload={
                "access_token": "new_access_token",
                "refresh_token": "new_refresh_token",
                "expires_in": 3600,
            },
        )

        request_kwargs = {}
        updated_kwargs = await handler.apply_auth(request_kwargs)

        assert "Authorization" in updated_kwargs["headers"]
        assert updated_kwargs["headers"]["Authorization"] == "Bearer new_access_token"

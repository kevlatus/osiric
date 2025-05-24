import logging
import time
from typing import Dict, Any, Optional
import aiohttp

from .common import AuthenticationHandler


class OAuthPasswordCredentialsHandler(AuthenticationHandler):
    """Handles OAuth 2.0 authentication using the Resource Owner Password Credentials grant."""

    def __init__(
            self,
            token_url: str,
            client_id: str,
            client_secret: str,
            username: str,
            password: str,
            scope: Optional[str] = None,
            token_prefix: str = "Bearer",
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.scope = scope
        self.token_prefix = token_prefix

        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0

        logging.info(
            f"Initialized OAuthPasswordCredentialsHandler for client {client_id}"
        )

    async def _fetch_token(self) -> None:
        """Fetch a new token from the authorization server."""
        payload = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password,
        }

        if self.scope:
            payload["scope"] = self.scope

        async with aiohttp.ClientSession() as session:
            async with session.post(self.token_url, data=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise RuntimeError(f"Failed to obtain OAuth token: {error_text}")

                token_data = await response.json()
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
                expires_in = token_data.get("expires_in", 3600)
                self.expires_at = time.time() + expires_in - 60  # Buffer of 60 seconds

                logging.info("Successfully obtained OAuth token")

    async def _refresh_token_if_needed(self) -> None:
        """Check if token is expired and refresh if needed."""
        if self.access_token is None:
            await self._fetch_token()
        elif time.time() > self.expires_at and self.refresh_token:
            # Refresh the token
            payload = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(self.token_url, data=payload) as response:
                    if response.status != 200:
                        # If refresh fails, try password grant again
                        logging.warning("Token refresh failed, obtaining new token")
                        await self._fetch_token()
                    else:
                        token_data = await response.json()
                        self.access_token = token_data.get("access_token")
                        self.refresh_token = token_data.get(
                            "refresh_token", self.refresh_token
                        )
                        expires_in = token_data.get("expires_in", 3600)
                        self.expires_at = time.time() + expires_in - 60
                        logging.info("Successfully refreshed OAuth token")

    async def apply_auth(
            self,
            request_kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add OAuth token to request headers."""
        await self._refresh_token_if_needed()

        headers = request_kwargs.get("headers", {}) or {}
        headers["Authorization"] = f"{self.token_prefix} {self.access_token}"
        request_kwargs["headers"] = headers

        return request_kwargs

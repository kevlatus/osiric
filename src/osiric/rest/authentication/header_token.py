import logging
from typing import Dict, Any, Optional

from aiohttp import ClientSession

from .common import AuthenticationHandler


class HeaderTokenAuthHandler(AuthenticationHandler):
    """Applies authentication via an Authorization header (e.g., Bearer token)."""

    def __init__(
        self,
        token: str,
        header_name: str = "Authorization",
        scheme: Optional[str] = None,
    ):
        self.header_name = header_name
        self.header_value = f"{token}"
        if scheme:
            self.header_value = f"{scheme} {self.header_value}"
        logging.info(
            f"Initialized HeaderTokenAuthHandler with header '{header_name}' and scheme '{scheme}'."
        )

    async def apply_auth(
        self,
        request_kwargs: Dict[str, Any],
        session: Optional[ClientSession] = None,
    ) -> Dict[str, Any]:
        headers = request_kwargs.get("headers", {}) or {}  # Ensure headers dict exists
        headers[self.header_name] = self.header_value
        request_kwargs["headers"] = headers
        return request_kwargs

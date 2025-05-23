from typing import Dict, Any, Optional

from aiohttp import ClientSession

from ..authentication import AuthenticationHandler


class NoAuthHandler(AuthenticationHandler):
    """Authentication handler that applies no authentication."""

    async def apply_auth(
        self,
        request_kwargs: Dict[str, Any],
        session: Optional[ClientSession] = None,
    ) -> Dict[str, Any]:
        return request_kwargs

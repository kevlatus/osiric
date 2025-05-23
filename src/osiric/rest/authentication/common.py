from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from aiohttp import ClientSession


class AuthenticationHandler(ABC):
    """Abstract Base Class for handling authentication in API requests."""

    @abstractmethod
    async def apply_auth(
        self,
        request_kwargs: Dict[str, Any],
        session: Optional[ClientSession] = None,
    ) -> Dict[str, Any]:
        """Modifies request kwargs to include authentication details."""
        pass

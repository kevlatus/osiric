from abc import ABC, abstractmethod
from typing import Generic, Optional, Dict, Any

import aiohttp

from ...common import StateType


class PaginationStrategy(Generic[StateType], ABC):
    """Abstract Base Class for handling API pagination."""

    @abstractmethod
    def get_initial_request_args(
        self,
        base_url: str,
        endpoint: str,
        base_params: Optional[Dict],
        base_json: Optional[Any],
        base_headers: Optional[Dict],
        initial_state: Optional[StateType],
    ) -> Dict[str, Any]:
        """Gets kwargs for the *first* API request, potentially using initial_state."""
        pass

    @abstractmethod
    async def get_next_request_args(
        self,
        last_response: aiohttp.ClientResponse,
        last_request_url: str,
    ) -> Optional[Dict[str, Any]]:
        """Gets kwargs for the *next* API request based on the last response, or None if done."""
        pass

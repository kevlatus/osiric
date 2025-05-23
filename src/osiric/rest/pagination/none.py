import copy
import logging
from typing import Any, Optional, Dict
from urllib.parse import urljoin

from aiohttp import ClientResponse

from .common import PaginationStrategy


class NoPaginationStrategy(PaginationStrategy[Any]):
    """Pagination strategy for APIs that return all data in a single response."""

    def __init__(self, method: str = "GET", state_filter_param: Optional[str] = None):
        self._method = method.upper()
        self._state_filter_param = state_filter_param
        logging.info(
            f"Initialized NoPaginationStrategy. State filter param: {state_filter_param}"
        )

    def get_initial_request_args(
        self,
        base_url: str,
        endpoint: str,
        base_params: Optional[Dict],
        base_json: Optional[Any],
        base_headers: Optional[Dict],
        initial_state: Optional[Any],
    ) -> Dict[str, Any]:
        full_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
        params = copy.deepcopy(base_params) or {}
        if self._state_filter_param and initial_state is not None:
            logging.info(
                f"Applying initial state '{initial_state}' to param '{self._state_filter_param}'"
            )
            params[self._state_filter_param] = initial_state
        logging.debug(
            f"NoPaginationStrategy: Initial request args for URL: {full_url}, Params: {params}"
        )
        return {
            "method": self._method,
            "url": full_url,
            "params": params,
            "json": base_json,
            "headers": base_headers,
        }

    async def get_next_request_args(
        self,
        last_response: ClientResponse,
        last_request_url: str,
    ) -> Optional[Dict[str, Any]]:
        logging.debug("NoPaginationStrategy: No next page.")
        return None

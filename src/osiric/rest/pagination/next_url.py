import copy
import logging
from typing import Any, List, Union, Optional, Dict, Generic
from urllib.parse import urljoin

from aiohttp import ClientResponse

from ...common import StateType

from ...util import get_nested_key
from .common import PaginationStrategy
from ..parsing import ResponseDataParser


class BaseNextUrlPaginationStrategy(PaginationStrategy[StateType], Generic[StateType]):
    """Base class for pagination strategies that follow 'next URL' links, now with ResponseDataParser support."""

    def __init__(
        self,
        next_url_key: Union[str, List[str]],
        data_parser: ResponseDataParser,
        method: str = "GET",
        state_filter_param: Optional[str] = None,
        stop_if_empty_page: bool = True,
    ):
        if not next_url_key:
            raise ValueError("NextUrlPaginationStrategy requires 'next_url_key'.")
        self.next_url_key = next_url_key
        self.data_parser = data_parser
        self._method = method.upper()
        self._state_filter_param = state_filter_param
        self.stop_if_empty_page = stop_if_empty_page
        logging.info(
            f"Initialized {self.__class__.__name__} with key: {next_url_key}. State filter param: {state_filter_param}, stop_if_empty_page: {stop_if_empty_page}"
        )

    def get_initial_request_args(
        self,
        base_url: str,
        endpoint: str,
        base_params: Optional[Dict],
        base_json: Optional[Any],
        base_headers: Optional[Dict],
        initial_state: Optional[StateType],
    ) -> Dict[str, Any]:
        full_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
        params = copy.deepcopy(base_params) or {}
        if self._state_filter_param and initial_state is not None:
            logging.info(
                f"Applying initial state '{initial_state}' to initial param '{self._state_filter_param}'"
            )
            params[self._state_filter_param] = initial_state
        logging.debug(
            f"{self.__class__.__name__}: Initial request args for URL: {full_url}, Params: {params}"
        )
        return {
            "method": self._method,
            "url": full_url,
            "params": params,
            "json": base_json,
            "headers": base_headers,
        }

    async def _process_next_url(
        self,
        next_page_value: Optional[str],
        last_request_url: str,
    ) -> Optional[Dict[str, Any]]:
        """Process the next URL value and create request args if valid."""
        if isinstance(next_page_value, str) and next_page_value:
            # Handle both absolute and relative URLs
            if next_page_value.startswith(("http://", "https://")):
                next_url = next_page_value
            else:
                # Ensure relative URLs are joined correctly with the last request's base URL
                next_url = urljoin(last_request_url, next_page_value)

            logging.info(f"{self.__class__.__name__}: Found next page URL: {next_url}")
            return {
                "method": self._method,
                "url": next_url,
                "params": None,
                "json": None,
                "headers": None,
            }
        else:
            logging.info(
                f"{self.__class__.__name__}: No next page URL found using key '{self.next_url_key}'."
            )
            return None

    async def get_next_request_args(
        self,
        last_response: ClientResponse,
        last_request_url: str,
    ) -> Optional[Dict[str, Any]]:
        """Must be implemented by subclasses to extract the next URL."""
        raise NotImplementedError("Subclasses must implement get_next_request_args")


class BodyNextUrlPaginationStrategy(
    BaseNextUrlPaginationStrategy[StateType], Generic[StateType]
):
    """Paginates by following a 'next URL' link found in the response body. Uses ResponseDataParser for record extraction."""

    async def get_next_request_args(
        self,
        last_response: ClientResponse,
        last_request_url: str,
    ) -> Optional[Dict[str, Any]]:
        last_response_data = await last_response.json()
        next_page_value = get_nested_key(last_response_data, self.next_url_key)

        # Use the data parser to extract records and optionally stop if empty
        if self.stop_if_empty_page:
            try:
                records_data = await self.data_parser.parse_records(last_response)
            except Exception as e:
                logging.warning(
                    f"BodyNextUrlPaginationStrategy: Failed to parse records from response: {e}. Assuming end of pagination."
                )
                return None
            num_received = 0
            if isinstance(records_data, list):
                num_received = len(records_data)
            elif records_data is None:
                num_received = 0
            else:
                logging.warning(
                    f"BodyNextUrlPaginationStrategy: Could not determine number of received records. "
                    f"Expected a list, found: {type(records_data)}. Assuming end of pagination."
                )
                return None
            logging.debug(
                f"BodyNextUrlPaginationStrategy: Received {num_received} records."
            )
            if num_received == 0:
                logging.info(
                    "BodyNextUrlPaginationStrategy: Received 0 records. Assuming end of pagination."
                )
                return None

        return await self._process_next_url(next_page_value, last_request_url)


class HeaderNextUrlPaginationStrategy(
    BaseNextUrlPaginationStrategy[StateType], Generic[StateType]
):
    """Paginates by following a 'next URL' link found in the response headers. Uses ResponseDataParser for record extraction."""

    async def get_next_request_args(
        self,
        last_response: ClientResponse,
        last_request_url: str,
    ) -> Optional[Dict[str, Any]]:
        # Extract the next URL from headers
        if isinstance(self.next_url_key, str):
            # Simple case: direct header name
            next_page_value = last_response.headers.get(self.next_url_key)
        else:
            # Handle list path through headers (unlikely but for API consistency)
            headers_dict = dict(last_response.headers)
            next_page_value = get_nested_key(headers_dict, self.next_url_key)

        # Use the data parser to extract records and optionally stop if empty
        if self.stop_if_empty_page:
            try:
                records_data = await self.data_parser.parse_records(last_response)
            except Exception as e:
                logging.warning(
                    f"HeaderNextUrlPaginationStrategy: Failed to parse records from response: {e}. Assuming end of pagination."
                )
                return None
            num_received = 0
            if isinstance(records_data, list):
                num_received = len(records_data)
            elif records_data is None:
                num_received = 0
            else:
                logging.warning(
                    f"HeaderNextUrlPaginationStrategy: Could not determine number of received records. "
                    f"Expected a list, found: {type(records_data)}. Assuming end of pagination."
                )
                return None
            logging.debug(
                f"HeaderNextUrlPaginationStrategy: Received {num_received} records."
            )
            if num_received == 0:
                logging.info(
                    "HeaderNextUrlPaginationStrategy: Received 0 records. Assuming end of pagination."
                )
                return None

        return await self._process_next_url(next_page_value, last_request_url)

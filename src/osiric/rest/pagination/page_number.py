import copy
import logging
from typing import Any, List, Union, Optional, Dict
from urllib.parse import urljoin

from ...util import get_nested_key
from .common import PaginationStrategy


class PageNumberPaginationStrategy(PaginationStrategy[Any]):
    """
    Paginates using a page number query parameter.
    Stops when a page returns no records (if stop_if_empty_page is True).
    """

    def __init__(
        self,
        method: str = "GET",
        page_param_name: str = "page",
        initial_page_number: int = 1,
        page_size_param_name: Optional[str] = None,
        page_size_value: Optional[int] = None,
        state_filter_param: Optional[str] = None,
        response_records_key: Optional[Union[str, List[str]]] = None,
        stop_if_empty_page: bool = True,
    ):
        """
        Initializes the PageNumberPaginationStrategy.

        Args:
            method (str): HTTP method for requests (e.g., "GET").
            page_param_name (str): Name of the query parameter for the page number.
            initial_page_number (int): The page number to start with (e.g., 1 for 1-indexed, 0 for 0-indexed).
            page_size_param_name (Optional[str]): Name of the query parameter for page size/limit.
            page_size_value (Optional[int]): Value for the page size/limit.
            state_filter_param (Optional[str]): Query parameter name to filter by initial_state on the first request.
            response_records_key (Optional[Union[str, List[str]]]): Key (or path of keys) to find the list of records
                in the response JSON. If None, the entire response is assumed to be the list of records.
                Used to determine if a page is empty.
            stop_if_empty_page (bool): If True, pagination stops if a page returns zero records
                or if records cannot be determined as a list.
        """
        if initial_page_number < 0:
            raise ValueError("initial_page_number must be non-negative.")
        if page_size_value is not None and page_size_value <= 0:
            raise ValueError("page_size_value must be positive if provided.")

        self._method = method.upper()
        self.page_param_name = page_param_name
        self.current_page_number = initial_page_number
        self._initial_page_number = initial_page_number

        self.page_size_param_name = page_size_param_name
        self.page_size_value = page_size_value

        self._state_filter_param = state_filter_param
        self._response_records_key = response_records_key
        self.stop_if_empty_page = stop_if_empty_page

        # Store base request details needed for subsequent pages
        self._base_url: str = ""
        self._endpoint: str = ""
        self._base_params: Dict[str, Any] = {}
        self._base_json: Optional[Any] = None
        self._base_headers: Optional[Dict[str, Any]] = {}

        logging.info(
            f"Initialized PageNumberPaginationStrategy: Method='{self._method}', "
            f"Page Param='{self.page_param_name}', Initial Page={self._initial_page_number}, "
            f"Page Size Param='{self.page_size_param_name}', Page Size Value={self.page_size_value}, "
            f"State Filter='{self._state_filter_param}', Records Key='{self._response_records_key}', "
            f"Stop if Empty Page={self.stop_if_empty_page}"
        )

    def get_initial_request_args(
        self,
        base_url: str,
        endpoint: str,
        base_params: Optional[Dict[str, Any]],
        base_json: Optional[Any],
        base_headers: Optional[Dict[str, Any]],
        initial_state: Optional[Any],
    ) -> Dict[str, Any]:
        # Store base details and reset page number for the start of a new run
        self._base_url = base_url
        self._endpoint = endpoint
        self._base_params = copy.deepcopy(base_params) or {}
        self._base_json = copy.deepcopy(base_json)
        self._base_headers = copy.deepcopy(base_headers) or {}

        self.current_page_number = self._initial_page_number  # Reset page number

        full_url = urljoin(self._base_url.rstrip("/") + "/", self._endpoint.lstrip("/"))
        params = copy.deepcopy(self._base_params)

        # Add page number
        params[self.page_param_name] = self.current_page_number

        # Add page size if configured
        if self.page_size_param_name and self.page_size_value is not None:
            params[self.page_size_param_name] = self.page_size_value

        # Apply initial state filter if configured
        if self._state_filter_param and initial_state is not None:
            logging.info(
                f"Applying initial state '{initial_state}' to initial param '{self._state_filter_param}'"
            )
            params[self._state_filter_param] = initial_state

        logging.debug(
            f"PageNumberPaginationStrategy: Initial request args for URL: {full_url}, Params: {params}"
        )
        return {
            "method": self._method,
            "url": full_url,
            "params": params,
            "json": self._base_json,
            "headers": self._base_headers,
        }

    async def get_next_request_args(
        self,
        last_response_data: Any,  # Can be Dict or List from response.json()
        last_request_url: str,  # Not used by this strategy
    ) -> Optional[Dict[str, Any]]:

        if self.stop_if_empty_page:
            # Determine how many records were actually received
            records_data = get_nested_key(
                last_response_data, self._response_records_key
            )

            num_received = 0
            if isinstance(records_data, list):
                num_received = len(records_data)
            elif records_data is None and self._response_records_key is None:
                # If no key specified, assume the root of the response is the list/data
                # _get_nested_key_utility(data, None) should return data.
                # So, if last_response_data was a list, records_data would be that list.
                # This branch handles if last_response_data itself was None.
                if isinstance(
                    last_response_data, list
                ):  # Should be caught by isinstance(records_data, list)
                    num_received = len(
                        last_response_data
                    )  # Defensive, may be redundant
                else:  # last_response_data was None or not a list
                    logging.warning(
                        "PageNumberPaginationStrategy: Could not determine number of received records "
                        "(response root is not a list and no records key specified, or root is None). "
                        "Assuming end of pagination."
                    )
                    return None
            else:
                # Key was specified but not found, or value at key is not a list.
                # Or, no key specified and response root (records_data) is not a list.
                logging.warning(
                    f"PageNumberPaginationStrategy: Could not determine number of received records. "
                    f"Expected a list at key '{self._response_records_key}' (or response root if no key). "
                    f"Found: {type(records_data)}. Assuming end of pagination."
                )
                return None

            logging.debug(
                f"PageNumberPaginationStrategy: Received {num_received} records."
            )

            if num_received == 0:
                logging.info(
                    "PageNumberPaginationStrategy: Received 0 records. Assuming end of pagination."
                )
                return None

        # Increment page number for the next request
        self.current_page_number += 1

        # Prepare args for the next request
        full_url = urljoin(self._base_url.rstrip("/") + "/", self._endpoint.lstrip("/"))
        params = copy.deepcopy(self._base_params)

        # Add new page number
        params[self.page_param_name] = self.current_page_number

        # Add page size if configured (usually constant across pages)
        if self.page_size_param_name and self.page_size_value is not None:
            params[self.page_size_param_name] = self.page_size_value

        logging.info(
            f"PageNumberPaginationStrategy: Requesting next page number {self.current_page_number}"
        )
        return {
            "method": self._method,
            "url": full_url,
            "params": params,
            "json": None,
            "headers": self._base_headers,
        }

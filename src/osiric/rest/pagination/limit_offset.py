import copy
import logging
from typing import Any, Optional, Union, List, Dict
from urllib.parse import urljoin

from ...util import get_nested_key
from .common import PaginationStrategy


class LimitOffsetPaginationStrategy(PaginationStrategy[Any]):
    """
    Paginates using limit and offset query parameters.
    Stops when the number of records received is less than the limit.
    """

    def __init__(
        self,
        method: str = "GET",
        limit_param_name: str = "limit",
        offset_param_name: str = "offset",
        limit_value: int = 100,
        initial_offset: int = 0,
        state_filter_param: Optional[str] = None,
        response_records_key: Optional[Union[str, List[str]]] = None,
    ):
        """
        Initializes the strategy. See original code for Args docstring.
        """
        if limit_value <= 0:
            raise ValueError("limit_value must be positive.")
        if initial_offset < 0:
            raise ValueError("initial_offset cannot be negative.")

        self._method = method.upper()
        self.limit_param = limit_param_name
        self.offset_param = offset_param_name
        self.limit = limit_value
        self.current_offset = initial_offset  # Current offset for the *next* request
        self._initial_offset = (
            initial_offset  # Store initial offset separately for resets
        )
        self._state_filter_param = state_filter_param
        self._response_records_key = response_records_key

        # Store base request details needed for subsequent pages
        self._base_url = ""
        self._endpoint = ""
        self._base_params: Dict = {}
        self._base_json: Optional[Any] = None
        self._base_headers: Optional[Dict] = {}
        self._run_initial_state: Optional[Any] = (
            None  # Store initial state for the run if needed
        )

        logging.info(
            f"Initialized LimitOffsetPaginationStrategy: Limit={limit_value} ({limit_param_name}), "
            f"Initial Offset={initial_offset} ({offset_param_name}), State Filter: {state_filter_param}, "
            f"Records Key: {response_records_key}"
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
        # Store base details and reset offset for the start of a new run
        self._base_url = base_url
        self._endpoint = endpoint
        self._base_params = copy.deepcopy(base_params) or {}
        self._base_json = copy.deepcopy(
            base_json
        )  # JSON payload usually only for first request
        self._base_headers = copy.deepcopy(base_headers) or {}
        self._run_initial_state = (
            initial_state  # Store for potential re-use if needed later
        )
        self.current_offset = self._initial_offset  # Reset offset

        full_url = urljoin(self._base_url.rstrip("/") + "/", self._endpoint.lstrip("/"))
        params = copy.deepcopy(self._base_params)

        # Add limit and current (initial) offset
        params[self.limit_param] = self.limit
        params[self.offset_param] = self.current_offset

        # Apply initial state filter if configured
        if self._state_filter_param and initial_state is not None:
            logging.info(
                f"Applying initial state '{initial_state}' to initial param '{self._state_filter_param}'"
            )
            params[self._state_filter_param] = initial_state

        logging.debug(
            f"LimitOffsetPaginationStrategy: Initial request args for URL: {full_url}, Params: {params}"
        )
        # Pass base_json and base_headers for the first request
        return {
            "method": self._method,
            "url": full_url,
            "params": params,
            "json": self._base_json,
            "headers": self._base_headers,
        }

    async def get_next_request_args(
        self, last_response_data: Dict[str, Any], last_request_url: str
    ) -> Optional[Dict[str, Any]]:
        # Determine how many records were actually received to check if we are on the last page
        # Use the centralized utility function
        records_data = get_nested_key(last_response_data, self._response_records_key)

        num_received = 0
        if isinstance(records_data, list):
            num_received = len(records_data)
        elif records_data is None and self._response_records_key is None:
            # If no key specified, assume the root of the response is the list/data
            if isinstance(last_response_data, list):
                num_received = len(last_response_data)
            else:
                # Or maybe the API just returns a single object on the last page?
                # This logic might need adjustment based on specific API behavior.
                # For now, assume if it's not a list at the expected place, we can't count.
                logging.warning(
                    f"Could not determine number of received records (response root is not a list and no key specified). Assuming end of pagination."
                )
                return None
        else:
            # Key was specified but not found or not a list
            logging.warning(
                f"Could not determine number of received records from key '{self._response_records_key}' or value is not a list. Assuming end of pagination."
            )
            return None  # Cannot determine if more pages exist

        logging.debug(
            f"LimitOffsetPaginationStrategy: Received {num_received} records, limit was {self.limit}."
        )

        # Stop condition: Received fewer records than requested limit
        if num_received < self.limit:
            logging.info(
                f"LimitOffsetPaginationStrategy: Received {num_received} records (less than limit {self.limit}). Assuming end of pagination."
            )
            return None  # No more pages

        # Calculate the offset for the *next* request
        self.current_offset += self.limit  # Increment offset by the limit size

        # Prepare args for the next request
        full_url = urljoin(
            self._base_url.rstrip("/") + "/", self._endpoint.lstrip("/")
        )  # Reconstruct base URL
        params = copy.deepcopy(self._base_params)  # Start with base params again

        # Add limit and *new* offset
        params[self.limit_param] = self.limit
        params[self.offset_param] = self.current_offset

        # Re-apply initial state filter? Usually not needed for subsequent offset pages,
        # but depends on the API. If needed, use self._run_initial_state.
        # if self._state_filter_param and self._run_initial_state is not None:
        #    params[self._state_filter_param] = self._run_initial_state

        logging.info(
            f"LimitOffsetPaginationStrategy: Requesting next page with offset {self.current_offset}"
        )
        # Subsequent requests usually don't include the initial JSON payload
        # Use the original base headers for subsequent requests
        return {
            "method": self._method,
            "url": full_url,
            "params": params,
            "json": None,
            "headers": self._base_headers,
        }

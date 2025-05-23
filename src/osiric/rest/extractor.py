import asyncio
import logging
from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
    AsyncGenerator,
    Generic,
)

import aiohttp
import pydantic

from ..common import RecordType, StateType, ExtractionError
from ..extractor import DataExtractor
from .authentication import AuthenticationHandler, NoAuthHandler
from .certificates import NoClientCertificateProvider, ClientCertificateProvider
from .pagination import PaginationStrategy, NoPaginationStrategy
from .parsing import ResponseDataParser, ResponseStateParser
from .ssl import DefaultSSLContextFactory, SSLContextFactory


class RestApiExtractorConfig(pydantic.BaseModel):
    base_url: str
    endpoint: str
    method: str = "GET"
    base_headers: Optional[Dict[str, str]] = None
    base_params: Optional[Dict[str, Any]] = None
    base_json_payload: Optional[Any] = None
    timeout_seconds: int = 30
    ssl_verify: bool = True
    connector_limit: Optional[int] = None


class RestApiDataExtractor(
    DataExtractor[
        RecordType,
        StateType,
        RestApiExtractorConfig,
    ],
    Generic[RecordType, StateType],
):
    """
    Asynchronous extractor for REST APIs using configurable strategies.

    Inherits state update methods (_update_state_from_record, _update_state_from_batch)
    from BaseExtractor. Subclasses MUST implement the relevant state update methods.

    Expected base configuration keys:
        - base_url (str): Base URL of the API.
        - endpoint (str): Specific API endpoint path.
        - method (str, optional): HTTP method (default: 'GET').
        - base_headers (dict, optional): Headers to include in all requests.
        - base_params (dict, optional): Query parameters for the initial request.
        - base_json_payload (any, optional): JSON body for the initial request (for POST/PUT etc.).
        - timeout_seconds (int, optional): Request timeout (default: 30).
        - ssl_verify (bool, optional): Whether to verify SSL certs (default: True).
        - connector_limit (int, optional): Max concurrent connections (default: aiohttp default).
    """

    def __init__(
            self,
            config: RestApiExtractorConfig,
            data_parser: ResponseDataParser[RecordType],
            state_parser: ResponseStateParser[StateType],
            auth: AuthenticationHandler = NoAuthHandler(),
            pagination: Optional[PaginationStrategy[Any]] = None,  # Default handled below
            certificate: ClientCertificateProvider = NoClientCertificateProvider(),
            ssl_context: SSLContextFactory = DefaultSSLContextFactory(),
    ):
        super().__init__(config)

        if self.config.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")

        if not isinstance(auth, AuthenticationHandler):
            raise TypeError("Invalid auth_handler")
        self.auth_handler = auth

        # Default to NoPaginationStrategy if none provided
        if pagination is None:
            self.pagination_strategy = NoPaginationStrategy(method=self.config.method)
            logging.debug(
                "No pagination strategy provided, using NoPaginationStrategy."
            )
        elif not isinstance(pagination, PaginationStrategy):
            raise TypeError("Invalid pagination_strategy")
        else:
            self.pagination_strategy = pagination

        if not isinstance(data_parser, ResponseDataParser):
            raise TypeError("Invalid data_parser")
        self.data_parser = data_parser

        if not isinstance(state_parser, ResponseStateParser):
            raise TypeError("Invalid state_parser")
        self.state_parser = state_parser

        if not isinstance(certificate, ClientCertificateProvider):
            raise TypeError("Invalid cert_provider")
        self.cert_provider = certificate

        if not isinstance(ssl_context, SSLContextFactory):
            raise TypeError("Invalid ssl_context_factory")
        self.ssl_context_factory = ssl_context

        self._session: Optional[aiohttp.ClientSession] = None

        self.logger.info(
            f"Initialized RestApiExtractor for {self.config.method} {self.config.base_url}/{self.config.endpoint.lstrip('/')}"
        )
        self.logger.info(
            f" Strategies - Auth: {type(auth).__name__}, "
            f"Pagination: {type(self.pagination_strategy).__name__}, Parser: {type(data_parser).__name__}, "
            f"CertProvider: {type(certificate).__name__}, SSLFactory: {type(ssl_context).__name__}"
        )
        self.logger.info(
            f" Settings - Timeout: {self.config.timeout_seconds}s, SSL Verify: {self.config.ssl_verify}, Connector Limit: {self.config.connector_limit or 'Default'}"
        )

    async def _connect(self):
        """Creates or retrieves the internal aiohttp ClientSession."""
        if self._session is None or self._session.closed:
            self.logger.debug("Creating internal aiohttp ClientSession.")
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)

            try:
                ssl_param = self.ssl_context_factory.create_ssl_context(
                    ssl_verify=self.config.ssl_verify,
                    cert_provider=self.cert_provider,
                )
            except ExtractionError as e:
                logging.error(f"SSLContextFactory failed during connection setup: {e}")
                raise
            except Exception as e:
                logging.error(
                    f"Unexpected error from SSLContextFactory: {e}", exc_info=True
                )
                raise ExtractionError(f"SSLContextFactory error: {e}") from e

            connector_args = {"ssl": ssl_param}
            if (
                    self.config.connector_limit is not None
                    and self.config.connector_limit > 0
            ):
                connector_args["limit"] = self.config.connector_limit
                self.logger.info(
                    f"Setting TCPConnector connection limit to {self.config.connector_limit}"
                )
            elif (
                    self.config.connector_limit is not None
                    and self.config.connector_limit <= 0
            ):
                self.logger.warning("Ignoring non-positive connector_limit value.")

            try:
                connector = aiohttp.TCPConnector(**connector_args)
                # Pass base_headers to session if needed (alternative to passing in request)
                # Note: Headers passed in request_args take precedence over session headers.
                self._session = aiohttp.ClientSession(
                    timeout=timeout,
                    headers=self.config.base_headers,  # Session-wide base headers
                    connector=connector,
                    # Potential Optimization: Use faster JSON serializer if needed
                    # json_serialize=orjson.dumps if using orjson
                )
                self.logger.debug("New aiohttp ClientSession created.")
            except Exception as e:
                logging.error(
                    f"Failed to create aiohttp ClientSession: {e}", exc_info=True
                )
                raise ExtractionError(f"Failed to create ClientSession: {e}") from e

        return self._session

    async def _close(self) -> None:
        """Closes the internal aiohttp ClientSession if it's open."""
        if self._session and not self._session.closed:
            self.logger.info("Closing internal aiohttp ClientSession.")
            await self._session.close()
            self._session = None
            # Short sleep recommended by aiohttp docs after closing
            await asyncio.sleep(0.1)
            self.logger.debug("Internal aiohttp ClientSession closed.")
        else:
            self.logger.debug("No active internal aiohttp ClientSession to close.")

    async def _make_request(
            self,
            request_args: Dict[str, Any],
    ) -> Tuple[RecordType, StateType, Optional[dict], str]:
        """
        Makes a single HTTP request using the current session and handles response.

        Args:
            request_args: Dictionary of keyword arguments for aiohttp.ClientSession.request().
                          Must include 'url' and 'method'.

        Returns:
            Tuple containing the parsed JSON response (or potentially raw text/bytes
            if ResponseParser is adapted) and the final URL after redirects.

        Raises:
            ExtractionError: For HTTP errors (4xx, 5xx), connection issues, timeouts,
                             or JSON decoding errors.
        """

        session = await self._connect()  # Ensure session exists
        if not session:  # Should not happen if _connect works, but safety check
            raise ExtractionError("Failed to get valid session in _make_request.")

        # Apply authentication - make a copy to avoid modifying original args dict
        try:
            authed_request_args = await self.auth_handler.apply_auth(
                request_args.copy(),
                session,
            )
        except Exception as e:
            self.logger.error(f"Authentication handler failed: {e}", exc_info=True)
            raise ExtractionError(f"Authentication handler error: {e}") from e

        method = authed_request_args.get("method", "GET")
        url = authed_request_args.get("url")
        if not url:
            raise ExtractionError("Request arguments must include a 'url'.")

        # Log request details (be careful about logging sensitive data in headers/params/json)
        log_args = {
            k: v for k, v in authed_request_args.items() if k not in ["headers", "json"]
        }
        self.logger.debug(f"Making {method} request to {url} with args: {log_args}")
        # Add more detailed logging for headers/body if needed, but mask sensitive info.
        # if 'headers' in authed_request_args: self.logger.debug(f" Headers: {authed_request_args['headers']}") # MASK SENSITIVE HEADERS
        # if 'json' in authed_request_args: self.logger.debug(f" JSON Body: {authed_request_args['json']}") # MASK SENSITIVE DATA

        actual_url = url  # Placeholder for final URL after redirects
        try:
            async with session.request(**authed_request_args) as response:
                actual_url = str(response.url)  # Capture final URL
                self.logger.debug(
                    f"Received response: Status {response.status} for {actual_url}"
                )

                # Raise ExtractionError for bad status codes (4xx, 5xx)
                response.raise_for_status()

                data = await self.data_parser.parse_records(response)
                state = await self.state_parser.parse_state(response)
                next_request_args = (
                    await self.pagination_strategy.get_next_request_args(
                        response,
                        actual_url,
                    )
                )

                return data, state, next_request_args, actual_url

        except aiohttp.ClientResponseError as e:
            # Error raised by response.raise_for_status() (4xx/5xx)
            logging.error(
                f"HTTP Error {e.status} for {url} (final URL: {actual_url}): {e.message}",
                exc_info=False,
            )  # exc_info=False as stack trace isn't usually helpful here
            # Consider reading response body for more details if available and useful
            # try: error_body = await response.text()
            # except: error_body = "(Could not read error body)"
            # logger.error(f"Error response body: {error_body[:500]}") # Log snippet
            raise ExtractionError(
                f"HTTP Error {e.status} requesting {url} (final: {actual_url}): {e.message}"
            ) from e
        except aiohttp.ClientConnectionError as e:
            # Errors like DNS resolution failure, TCP connection refused, etc.
            logging.error(f"Connection Error requesting {url}: {e}", exc_info=False)
            raise ExtractionError(f"Connection Error requesting {url}: {e}") from e
        except asyncio.TimeoutError as e:
            # Timeout during connection or request sending (before response received)
            logging.error(f"Request timed out for {url}", exc_info=False)
            raise ExtractionError(f"Request timed out for {url}") from e
        except Exception as e:
            # Catch-all for other unexpected errors during the request process
            logging.error(
                f"Unexpected error during request to {url}: {e}", exc_info=True
            )
            raise ExtractionError(f"Unexpected error requesting {url}: {e}") from e

    async def _extract_data(
            self,
            initial_state: Optional[StateType] = None,
    ) -> AsyncGenerator[RecordType, None]:
        """
        Internal method to fetch data using pagination and parse records.

        - Gets initial request arguments from the pagination strategy.
        - Loops while the pagination strategy provides next request arguments.
        - Makes requests using `_make_request`.
        - Parses records from the response using the response parser.
        - Yields each parsed record.
        - Calls `self._update_state_from_batch(response_data)` after processing each page's response.
        - Handles `ExtractionError` during page processing and stops iteration.

        Args:
            initial_state: The state provided for the current extraction run.

        Yields:
            Dict[str, Any]: Parsed records from the API.

        Potential Improvement: Implement rate limiting logic here (e.g., asyncio.sleep based on config).
        Potential Improvement: Add retry logic for transient errors based on ErrorHandler strategy.
        """

        self.logger.info("Starting data extraction loop.")
        current_request_args: Optional[Dict] = None
        try:
            # Get arguments for the very first request
            current_request_args = self.pagination_strategy.get_initial_request_args(
                self.config.base_url,
                self.config.endpoint,
                self.config.base_params,
                self.config.base_json_payload,
                self.config.base_headers,
                initial_state,
            )
        except Exception as e:
            logging.error(
                f"Pagination strategy failed to get initial request args: {e}",
                exc_info=True,
            )
            raise ExtractionError(f"Failed to get initial request args: {e}") from e

        page_number = 1
        while current_request_args:
            request_url_for_log = current_request_args.get(
                "url", "N/A"
            )  # URL before potential redirects
            self.logger.info(
                f"Processing page/batch {page_number} (URL: {request_url_for_log})..."
            )
            # TODO: Add rate limiting sleep here if configured
            # await asyncio.sleep(self.config.get('rate_limit_delay', 0))

            try:
                records, state, next_request_args, actual_request_url = (
                    await self._make_request(current_request_args)
                )

                try:
                    self._update_state(state)
                    yield records  # Yield record to the caller of extract()
                except Exception as parse_err:
                    logging.error(
                        f"Response parser failed for page/batch {page_number} ({actual_request_url}): {parse_err}",
                        exc_info=True,
                    )
                    # Decide whether to stop or continue? For now, stop.
                    raise ExtractionError(
                        f"Response parser failed on page/batch {page_number}: {parse_err}"
                    ) from parse_err

                # --- Get next request args from pagination strategy ---
                try:
                    current_request_args = next_request_args
                    if current_request_args:
                        self.logger.debug(
                            f"Pagination strategy provided args for next page/batch."
                        )
                    else:
                        self.logger.info(
                            "Pagination strategy indicated no more pages/batches."
                        )
                except Exception as page_err:
                    logging.error(
                        f"Pagination strategy failed to get next request args after page/batch {page_number}: {page_err}",
                        exc_info=True,
                    )
                    raise ExtractionError(
                        f"Failed to get next request args after page/batch {page_number}: {page_err}"
                    ) from page_err

                page_number += 1

            except ExtractionError as e:
                # Errors raised by _make_request, parser, or state update
                self.logger.error(
                    f"Stopping extraction loop due to error processing page/batch {page_number} ({request_url_for_log}): {e}"
                )
                # TODO: Implement retry logic here based on error type/strategy
                raise e  # Stop processing further pages on error
            except Exception as e:
                # Catch any other unexpected errors during page processing
                self.logger.error(
                    f"Unexpected error processing page/batch {page_number} ({request_url_for_log}): {e}",
                    exc_info=True,
                )
                raise e  # Stop processing further pages

            # Optional small sleep between pages to be polite to the API
            # await asyncio.sleep(0.05) # Adjust as needed

        self.logger.info(
            f"Finished data extraction loop after processing {page_number - 1} pages/batches."
        )

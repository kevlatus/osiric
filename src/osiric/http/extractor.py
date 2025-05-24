import asyncio
import logging
from abc import abstractmethod, ABC
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

from ..common import ExtractionError, RecordType, StateType
from ..extractor import DataExtractor
from .authentication import AuthenticationHandler, NoAuthHandler
from .certificates import NoClientCertificateProvider, ClientCertificateProvider
from .ssl import DefaultSSLContextFactory, SSLContextFactory


class HttpDataExtractorConfig(pydantic.BaseModel):
    """Base configuration for HTTP-based extractors"""

    timeout_seconds: int = 30
    ssl_verify: bool = True
    connector_limit: Optional[int] = None
    base_headers: Optional[Dict[str, str]] = None


class HttpDataExtractor(
    DataExtractor[
        RecordType,
        StateType,
        HttpDataExtractorConfig,
    ],
    Generic[RecordType, StateType],
    ABC,
):
    """
    Base extractor for HTTP-based data sources.

    Provides common HTTP functionality including
    - Session management
    - Basic HTTP request handling
    - SSL/TLS configuration
    - Authentication integration

    Subclasses should implement:
    - _process_response: To convert HTTP responses to records and state
    - _get_initial_request_args: To provide initial request arguments
    - _get_next_request_args: To implement pagination or batching
    """

    def __init__(
        self,
        config: HttpDataExtractorConfig,
        auth: AuthenticationHandler = NoAuthHandler(),
        certificate: ClientCertificateProvider = NoClientCertificateProvider(),
        ssl_context: SSLContextFactory = DefaultSSLContextFactory(),
    ):
        super().__init__(config)

        if self.config.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")

        if not isinstance(auth, AuthenticationHandler):
            raise TypeError("Invalid auth_handler")
        self.auth_handler = auth

        if not isinstance(certificate, ClientCertificateProvider):
            raise TypeError("Invalid cert_provider")
        self.cert_provider = certificate

        if not isinstance(ssl_context, SSLContextFactory):
            raise TypeError("Invalid ssl_context_factory")
        self.ssl_context_factory = ssl_context

        self._session: Optional[aiohttp.ClientSession] = None

        self.logger.info(f"Initialized HttpExtractor")
        self.logger.info(
            f" Strategies - Auth: {type(auth).__name__}, "
            f"CertProvider: {type(certificate).__name__}, SSLFactory: {type(ssl_context).__name__}"
        )
        self.logger.info(
            f" Settings - Timeout: {self.config.timeout_seconds}s, SSL Verify: {self.config.ssl_verify}, "
            f"Connector Limit: {self.config.connector_limit or 'Default'}"
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
                # Pass base_headers to session if needed
                self._session = aiohttp.ClientSession(
                    timeout=timeout,
                    headers=self.config.base_headers,
                    connector=connector,
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
    ) -> Tuple[RecordType, StateType, str, Optional[Dict[str, Any]]]:
        """
        Makes a single HTTP request using the current session.

        Args:
            request_args: Dictionary of keyword arguments for aiohttp.ClientSession.request().
                          Must include 'url' and 'method'.

        Returns:
            Tuple containing the response object and the final URL after redirects.

        Raises:
            ExtractionError: For HTTP errors (4xx, 5xx), connection issues, timeouts.
        """
        session = await self._connect()
        if not session:
            raise ExtractionError("Failed to get valid session in _make_request.")

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

        # Log request details (be careful about logging sensitive data)
        log_args = {
            k: v for k, v in authed_request_args.items() if k not in ["headers", "json"]
        }
        self.logger.debug(f"Making {method} request to {url} with args: {log_args}")

        actual_url = url  # Placeholder for final URL after redirects
        try:
            async with session.request(**authed_request_args) as response:
                actual_url = str(response.url)  # Capture final URL
                self.logger.debug(
                    f"Received response: Status {response.status} for {actual_url}"
                )

                # Raise ExtractionError for bad status codes (4xx, 5xx)
                response.raise_for_status()

                records, state, next_request_args = await self._process_response(
                    response, actual_url
                )

                return records, state, actual_url, next_request_args

        except aiohttp.ClientResponseError as e:
            logging.error(
                f"HTTP Error {e.status} for {url} (final URL: {actual_url}): {e.message}",
                exc_info=False,
            )
            raise ExtractionError(
                f"HTTP Error {e.status} requesting {url} (final: {actual_url}): {e.message}"
            ) from e
        except aiohttp.ClientConnectionError as e:
            logging.error(f"Connection Error requesting {url}: {e}", exc_info=False)
            raise ExtractionError(f"Connection Error requesting {url}: {e}") from e
        except asyncio.TimeoutError as e:
            logging.error(f"Request timed out for {url}", exc_info=False)
            raise ExtractionError(f"Request timed out for {url}") from e
        except Exception as e:
            logging.error(
                f"Unexpected error during request to {url}: {e}", exc_info=True
            )
            raise ExtractionError(f"Unexpected error requesting {url}: {e}") from e

    @abstractmethod
    async def _process_response(
        self,
        response: aiohttp.ClientResponse,
        url: str,
    ) -> Tuple[RecordType, StateType, Optional[Dict[str, Any]]]:
        """
        Process the HTTP response and extract records, state, and next request arguments.

        Args:
            response: The HTTP response object.
            url: The URL of the request (after potential redirects).

        Returns:
            Tuple containing:
              - records: The extracted records
              - state: The extracted state
              - next_request_args: Arguments for the next request, or None if done

        This method must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _process_response")

    @abstractmethod
    async def _get_initial_request_args(
        self,
        initial_state: Optional[StateType] = None,
    ) -> Dict[str, Any]:
        """
        Get the request arguments for the initial HTTP request.

        Args:
            initial_state: The initial state for extraction.

        Returns:
            Dictionary of arguments for the initial HTTP request.

        This method must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _get_initial_request_args")

    async def _extract_data(
        self,
        initial_state: Optional[StateType] = None,
    ) -> AsyncGenerator[RecordType, None]:
        """
        Extracts data by making HTTP requests and processing responses.

        Args:
            initial_state: The initial state for extraction.

        Yields:
            Records extracted from HTTP responses.
        """
        self.logger.info("Starting HTTP data extraction loop.")

        try:
            current_request_args = await self._get_initial_request_args(initial_state)
        except Exception as e:
            logging.error(f"Failed to get initial request args: {e}", exc_info=True)
            raise ExtractionError(f"Failed to get initial request args: {e}") from e

        page_number = 1
        while current_request_args:
            request_url_for_log = current_request_args.get("url", "N/A")
            self.logger.info(
                f"Processing page/batch {page_number} (URL: {request_url_for_log})..."
            )

            try:
                records, state, actual_url, next_request_args = (
                    await self._make_request(current_request_args)
                )

                try:
                    self._update_state(state)
                    yield records

                except Exception as parse_err:
                    logging.error(
                        f"Response processing failed for page/batch {page_number} ({actual_url}): {parse_err}",
                        exc_info=True,
                    )
                    raise ExtractionError(
                        f"Response processing failed on page/batch {page_number}: {parse_err}"
                    ) from parse_err

                current_request_args = next_request_args
                if current_request_args:
                    self.logger.debug(f"Retrieved arguments for next page/batch.")
                else:
                    self.logger.info("No more pages/batches to process.")

                page_number += 1

            except ExtractionError as e:
                self.logger.error(
                    f"Stopping extraction loop due to error processing page/batch {page_number} ({request_url_for_log}): {e}"
                )
                raise e
            except Exception as e:
                self.logger.error(
                    f"Unexpected error processing page/batch {page_number} ({request_url_for_log}): {e}",
                    exc_info=True,
                )
                raise e

        self.logger.info(
            f"Finished HTTP data extraction loop after processing {page_number - 1} pages/batches."
        )

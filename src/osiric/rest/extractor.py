import logging
from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
    Generic,
)

import aiohttp

from ..common import RecordType, StateType
from ..http import (
    AuthenticationHandler,
    HttpDataExtractorConfig,
    HttpDataExtractor,
    SSLContextFactory,
    ClientCertificateProvider,
    NoAuthHandler,
    NoClientCertificateProvider,
    DefaultSSLContextFactory,
)
from .pagination import PaginationStrategy, NoPaginationStrategy
from .parsing import ResponseDataParser, ResponseStateParser


class RestApiDataExtractorConfig(HttpDataExtractorConfig):
    """Configuration for REST API extractors."""

    base_url: str
    endpoint: str
    method: str = "GET"
    base_params: Optional[Dict[str, Any]] = None
    base_json_payload: Optional[Any] = None


class RestApiDataExtractor(
    HttpDataExtractor[
        RecordType,
        StateType,
    ],
    Generic[RecordType, StateType],
):
    """
    Asynchronous extractor for REST APIs using configurable strategies.

    Expected configuration keys (in addition to HttpExtractorConfig):
        - base_url (str): Base URL of the API.
        - endpoint (str): Specific API endpoint path.
        - method (str, optional): HTTP method (default: 'GET').
        - base_params (dict, optional): Query parameters for the initial request.
        - base_json_payload (any, optional): JSON body for the initial request (for POST/PUT etc.).
    """

    def __init__(
        self,
        config: RestApiDataExtractorConfig,
        data_parser: ResponseDataParser[RecordType],
        state_parser: ResponseStateParser[StateType],
        auth: AuthenticationHandler = NoAuthHandler(),
        pagination: Optional[PaginationStrategy[Any]] = None,
        certificate: ClientCertificateProvider = NoClientCertificateProvider(),
        ssl_context: SSLContextFactory = DefaultSSLContextFactory(),
    ):
        super().__init__(
            config,
            auth=auth,
            certificate=certificate,
            ssl_context=ssl_context,
        )

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

        self.logger.info(
            f"Initialized RestApiExtractor for {self.config.method} {self.config.base_url}/{self.config.endpoint.lstrip('/')}"
        )
        self.logger.info(
            f" Strategies - Pagination: {type(self.pagination_strategy).__name__}, "
            f"Parser: {type(data_parser).__name__}"
        )

    async def _process_response(
        self,
        response: aiohttp.ClientResponse,
        url: str,
    ) -> Tuple[RecordType, StateType, Optional[Dict[str, Any]]]:
        """
        Process the HTTP response and extract records, state, and next request arguments.

        Implements the abstract method from HttpExtractor.

        Args:
            response: The HTTP response object.
            url: The URL of the request (after potential redirects).

        Returns:
            Tuple containing records, state, and next request arguments.
        """
        data = await self.data_parser.parse_records(response)
        state = await self.state_parser.parse_state(response)
        next_request_args = await self.pagination_strategy.get_next_request_args(
            response, url
        )

        return data, state, next_request_args

    async def _get_initial_request_args(
        self,
        initial_state: Optional[StateType] = None,
    ) -> Dict[str, Any]:
        """
        Get the request arguments for the initial HTTP request.

        Implements the abstract method from HttpExtractor.

        Args:
            initial_state: The initial state for extraction.

        Returns:
            Dictionary of arguments for the initial HTTP request.
        """
        return self.pagination_strategy.get_initial_request_args(
            self.config.base_url,
            self.config.endpoint,
            self.config.base_params,
            self.config.base_json_payload,
            self.config.base_headers,
            initial_state,
        )

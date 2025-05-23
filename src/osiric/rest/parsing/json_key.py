import logging
from typing import Any, List, Union, Optional, Sequence, Generic

from aiohttp import ClientResponse

from ...common import RecordType, ExtractionError, StateType
from ...util import get_nested_key
from .common import ResponseDataParser, ResponseStateParser


def parse_json_key(
    content: Any,
    data_key: Optional[Union[str, List[str]]] = None,
) -> Union[RecordType, Sequence[RecordType]]:
    records_data = get_nested_key(content, data_key)

    if records_data is None and data_key is not None:
        logging.warning(f"Data key '{data_key}' not found in response.")
        raise ExtractionError()

    return records_data


class JsonKeyResponseDataParser(ResponseDataParser[Union[dict, Sequence[dict]]]):
    """Parses records from a JSON response, expecting a list under a specified key."""

    def __init__(
        self,
        data_key: Optional[Union[str, List[str]]] = None,
    ):
        """
        Initializes the parser.

        Args:
            data_key: Dot-separated string or list of keys to locate the list of records.
                      If None, assumes the response root is the list of records (or a single record dict).
        """

        self.data_key = data_key
        logging.info(f"Initialized JsonKeyResponseParser with data_key: {data_key}")

    async def parse_records(
        self,
        response: ClientResponse,
    ) -> Union[dict, Sequence[dict]]:
        """Parses and yields records found at the specified data_key."""

        content = await response.json()
        records_data = parse_json_key(content, self.data_key)

        if isinstance(records_data, list) or isinstance(records_data, dict):
            result = records_data
        elif records_data is None and self.data_key is None:
            result = content
        else:
            logging.warning(
                f"Expected list or dict under key '{self.data_key}', got {type(records_data)}. Cannot parse records."
            )
            raise ExtractionError()

        return result


class JsonKeyResponseStateParser(ResponseStateParser[StateType], Generic[StateType]):
    """Parses state from a JSON response, expecting a list under a specified key."""

    def __init__(
        self,
        data_key: Optional[Union[str, List[str]]] = None,
    ):
        """
        Initializes the parser.

        Args:
            data_key: Dot-separated string or list of keys to locate the list of records.
                      If None, assumes the response root is the list of records (or a single record dict).
        """

        self.data_key = data_key
        logging.info(f"Initialized JsonKeyResponseParser with data_key: {data_key}")

    async def parse_state(
        self,
        response: ClientResponse,
    ) -> StateType:
        """Parses and yields records found at the specified data_key."""

        content = await response.json()
        return parse_json_key(content, self.data_key)

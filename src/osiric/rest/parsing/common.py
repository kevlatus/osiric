from abc import ABC, abstractmethod
from typing import Generic, Sequence, Union

from aiohttp import ClientResponse

from ...common import RecordType, StateType


class ResponseDataParser(Generic[RecordType], ABC):
    """Abstract Base Class for parsing records from an API response."""

    @abstractmethod
    async def parse_records(
        self,
        response: ClientResponse,
    ) -> Union[RecordType, Sequence[RecordType]]:
        """Parses and returns records from the response."""
        pass


class ResponseStateParser(Generic[StateType], ABC):
    async def parse_state(
        self,
        response: ClientResponse,
    ) -> StateType:
        """Parses and returns state from the response."""
        pass

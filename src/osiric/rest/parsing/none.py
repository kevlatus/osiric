from aiohttp import ClientResponse

from .common import ResponseStateParser

class NoResponseStateParser(ResponseStateParser[None]):
    async def parse_state(
        self,
        response: ClientResponse,
    ) -> None:
        return None

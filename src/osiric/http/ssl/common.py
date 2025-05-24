import ssl
from abc import ABC, abstractmethod
from typing import Union

from ..certificates import ClientCertificateProvider


class SSLContextFactory(ABC):
    """Abstract Base Class for creating SSL contexts for HTTPS requests."""

    @abstractmethod
    def create_ssl_context(
        self,
        ssl_verify: bool,
        cert_provider: ClientCertificateProvider,
    ) -> Union[ssl.SSLContext, bool]:
        """Creates an SSLContext or returns False to disable verification."""
        pass

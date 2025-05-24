from typing import Optional, Tuple

from .common import ClientCertificateProvider


class NoClientCertificateProvider(ClientCertificateProvider):
    """Provides no client certificate parameters."""

    def get_cert_params(self) -> Optional[Tuple[str, str, Optional[str]]]:
        return None

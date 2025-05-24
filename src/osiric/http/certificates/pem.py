import logging
from typing import Optional, Tuple

from .common import ClientCertificateProvider


class PEMFileClientCertificateProvider(ClientCertificateProvider):
    """Provides client certificate parameters from PEM files."""

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        key_password: Optional[str] = None,
    ):
        if not cert_path or not key_path:
            raise ValueError(
                "Both cert_path and key_path must be provided for PEMFileClientCertificateProvider."
            )
        # TODO: Add checks here to see if files actually exist?
        self.cert_path = cert_path
        self.key_path = key_path
        self.key_password = key_password
        logging.info(
            f"Initialized PEMFileClientCertificateProvider with cert: {cert_path}, key: {key_path}"
        )

    def get_cert_params(self) -> Optional[Tuple[str, str, Optional[str]]]:
        return self.cert_path, self.key_path, self.key_password

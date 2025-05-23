from abc import ABC, abstractmethod
from typing import Optional, Tuple


class ClientCertificateProvider(ABC):
    """Abstract Base Class for providing client-side SSL certificate details."""

    @abstractmethod
    def get_cert_params(self) -> Optional[Tuple[str, str, Optional[str]]]:
        """Returns (cert_path, key_path, key_password) or None."""
        pass

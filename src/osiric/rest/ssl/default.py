import logging
import ssl
from typing import Union

from ...common import ExtractionError
from ..certificates import ClientCertificateProvider
from .common import SSLContextFactory


class DefaultSSLContextFactory(SSLContextFactory):
    """Default factory for creating SSL contexts."""

    def create_ssl_context(
        self,
        ssl_verify: bool,
        cert_provider: ClientCertificateProvider,
    ) -> Union[ssl.SSLContext, bool]:
        """Creates a default SSL context, optionally loading client certs."""

        if not ssl_verify:
            logging.warning(
                "SSL verification DISABLED. This is insecure for production environments."
            )
            return False  # Disable SSL verification in aiohttp

        # Create a default context with standard security settings
        try:
            # ssl.PROTOCOL_TLS_CLIENT requires Python 3.6+
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            # Load default CAs provided by the system
            ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
            # Recommended modern security settings (may need adjustment based on target server)
            # ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2 # Requires Python 3.7+
            # Consider adding ciphers if needed: ssl_context.set_ciphers(...)
        except AttributeError:  # Fallback for older Python versions if needed
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            logging.warning(
                "Using ssl.create_default_context. Consider ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) for finer control."
            )

        # Attempt to load client certificate if provided
        cert_params = cert_provider.get_cert_params()
        if cert_params:
            cert_file, keyfile, key_password = cert_params
            logging.info(
                f"Attempting load client cert ('{cert_file}') and key ('{keyfile}')."
            )
            try:
                ssl_context.load_cert_chain(
                    certfile=cert_file,
                    keyfile=keyfile,
                    password=key_password,
                )
                logging.info("Client certificate and key loaded successfully.")
            except FileNotFoundError as e:
                logging.error(f"Client certificate or key file not found: {e}")
                raise ExtractionError(
                    f"Client certificate or key file not found: {e}"
                ) from e
            except ssl.SSLError as e:
                # This can happen for various reasons: wrong password, bad cert/key format, etc.
                logging.error(f"SSL Error loading client certificate/key: {e}")
                raise ExtractionError(
                    f"SSL Error loading client certificate/key: {e}"
                ) from e
            except Exception as e:
                logging.error(
                    f"Unexpected error loading client certificate/key: {e}",
                    exc_info=True,
                )
                raise ExtractionError(
                    f"Unexpected error loading client certificate/key: {e}"
                ) from e
        else:
            logging.debug("No client certificate parameters provided.")

        return ssl_context

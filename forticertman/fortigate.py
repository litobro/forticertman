"""Fortigate REST API client for certificate management."""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from forticertman.config import CertificateDeployment, FortigateConfig

logger = logging.getLogger(__name__)


class FortigateError(Exception):
    """Fortigate API error."""


class FortigateClient:
    """REST API client for Fortigate firewall."""

    def __init__(self, config: FortigateConfig) -> None:
        self.config = config
        self.base_url = config.base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_token}",
            "Content-Type": "application/json",
        })
        self.session.verify = config.verify_ssl
        self.timeout = config.timeout

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make an API request.

        Args:
            method: HTTP method.
            endpoint: API endpoint path.
            data: Request body data.
            params: Query parameters.

        Returns:
            Response JSON data.

        Raises:
            FortigateError: If the request fails.
        """
        url = f"{self.base_url}{endpoint}"
        logger.debug("%s %s", method, url)

        try:
            response = self.session.request(
                method,
                url,
                json=data,
                params=params,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.SSLError as e:
            raise FortigateError(
                f"SSL error connecting to {self.config.host}. "
                "Set verify_ssl: false in config if using self-signed cert."
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise FortigateError(
                f"Failed to connect to Fortigate at {self.config.host}:{self.config.port}"
            ) from e
        except requests.exceptions.HTTPError as e:
            error_msg = f"API request failed: {e}"
            if response.text:
                try:
                    error_data = response.json()
                    error_msg = f"API error: {error_data.get('error', response.text)}"
                except ValueError:
                    error_msg = f"API error: {response.text}"
            raise FortigateError(error_msg) from e
        except requests.exceptions.Timeout as e:
            raise FortigateError(
                f"Request timed out after {self.timeout}s"
            ) from e

    def test_connection(self) -> bool:
        """Test the connection to the Fortigate.

        Returns:
            True if connection is successful.
        """
        try:
            self._request("GET", "/api/v2/monitor/system/status")
            return True
        except FortigateError:
            return False

    def get_system_status(self) -> dict[str, Any]:
        """Get Fortigate system status.

        Returns:
            System status information.
        """
        result = self._request("GET", "/api/v2/monitor/system/status")
        return result.get("results", {})

    def list_certificates(self) -> list[dict[str, Any]]:
        """List all local certificates.

        Returns:
            List of certificate information.
        """
        result = self._request("GET", "/api/v2/cmdb/certificate/local")
        return result.get("results", [])

    def get_certificate(self, name: str) -> dict[str, Any] | None:
        """Get a specific certificate by name.

        Args:
            name: Certificate name.

        Returns:
            Certificate information or None if not found.
        """
        try:
            result = self._request("GET", f"/api/v2/cmdb/certificate/local/{name}")
            results = result.get("results", [])
            return results[0] if results else None
        except FortigateError:
            return None

    def upload_certificate(
        self,
        name: str,
        cert_pem: str,
        key_pem: str,
        password: str | None = None,
    ) -> dict[str, Any]:
        """Upload a certificate and private key.

        Args:
            name: Name for the certificate in Fortigate.
            cert_pem: Certificate in PEM format (can be fullchain).
            key_pem: Private key in PEM format.
            password: Optional password for encrypted key.

        Returns:
            Upload result.
        """
        logger.info("Uploading certificate: %s", name)

        # Base64 encode the certificate and key
        cert_b64 = base64.b64encode(cert_pem.encode()).decode()
        key_b64 = base64.b64encode(key_pem.encode()).decode()

        data: dict[str, Any] = {
            "type": "regular",
            "certname": name,
            "file_content": cert_b64,
            "key_file_content": key_b64,
            "scope": "global",
        }

        if password:
            data["password"] = password

        result = self._request(
            "POST",
            "/api/v2/monitor/vpn-certificate/local/import",
            data=data,
            params={"scope": "global"},
        )

        logger.info("Certificate uploaded successfully: %s", name)
        return result

    def delete_certificate(self, name: str) -> None:
        """Delete a certificate.

        Args:
            name: Certificate name.
        """
        logger.info("Deleting certificate: %s", name)
        self._request("DELETE", f"/api/v2/cmdb/certificate/local/{name}")
        logger.info("Certificate deleted: %s", name)

    def get_ssl_inspection_profiles(self) -> list[dict[str, Any]]:
        """List all SSL/SSH inspection profiles.

        Returns:
            List of profile information.
        """
        result = self._request("GET", "/api/v2/cmdb/firewall/ssl-ssh-profile")
        return result.get("results", [])

    def get_ssl_inspection_profile(self, name: str) -> dict[str, Any] | None:
        """Get a specific SSL inspection profile.

        Args:
            name: Profile name.

        Returns:
            Profile information or None if not found.
        """
        try:
            result = self._request("GET", f"/api/v2/cmdb/firewall/ssl-ssh-profile/{name}")
            results = result.get("results", [])
            return results[0] if results else None
        except FortigateError:
            return None

    def update_ssl_inspection_profile(
        self,
        profile_name: str,
        server_cert: str,
    ) -> None:
        """Update SSL inspection profile to use a new certificate.

        Args:
            profile_name: SSL inspection profile name.
            server_cert: Certificate name to use.
        """
        logger.info(
            "Updating SSL inspection profile '%s' to use certificate '%s'",
            profile_name,
            server_cert,
        )

        self._request(
            "PUT",
            f"/api/v2/cmdb/firewall/ssl-ssh-profile/{profile_name}",
            data={"server-cert": server_cert},
        )

        logger.info("SSL inspection profile updated successfully")

    def get_vips(self) -> list[dict[str, Any]]:
        """List all virtual IPs.

        Returns:
            List of VIP information.
        """
        result = self._request("GET", "/api/v2/cmdb/firewall/vip")
        return result.get("results", [])

    def update_vip_certificate(self, vip_name: str, server_cert: str) -> None:
        """Update VIP to use a new SSL certificate.

        Args:
            vip_name: VIP name.
            server_cert: Certificate name to use.
        """
        logger.info(
            "Updating VIP '%s' to use certificate '%s'",
            vip_name,
            server_cert,
        )

        self._request(
            "PUT",
            f"/api/v2/cmdb/firewall/vip/{vip_name}",
            data={"server-cert": server_cert},
        )

        logger.info("VIP certificate updated successfully")

    def deploy_certificate(
        self,
        cert_name: str,
        cert_pem: str,
        key_pem: str,
        deployments: list[CertificateDeployment],
    ) -> None:
        """Upload certificate and apply to all deployment targets.

        Args:
            cert_name: Name for the certificate.
            cert_pem: Certificate PEM content.
            key_pem: Private key PEM content.
            deployments: List of deployment targets.
        """
        # Generate a unique name with timestamp to allow rotation
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        versioned_name = f"{cert_name}_{timestamp}"

        # Upload the new certificate
        self.upload_certificate(versioned_name, cert_pem, key_pem)

        # Apply to each deployment target
        for deploy in deployments:
            if deploy.ssl_inspection and deploy.profile:
                self.update_ssl_inspection_profile(deploy.profile, versioned_name)
            if deploy.vip:
                self.update_vip_certificate(deploy.vip, versioned_name)

        # Clean up old certificates with same base name
        self._cleanup_old_certificates(cert_name, keep=versioned_name)

    def _cleanup_old_certificates(self, base_name: str, keep: str) -> None:
        """Remove old versions of a certificate.

        Args:
            base_name: Base certificate name (without timestamp).
            keep: Certificate name to keep.
        """
        certs = self.list_certificates()
        for cert in certs:
            name = cert.get("name", "")
            # Match certificates with same base name but different timestamp
            if name.startswith(f"{base_name}_") and name != keep:
                try:
                    self.delete_certificate(name)
                    logger.info("Removed old certificate: %s", name)
                except FortigateError as e:
                    # Certificate might be in use by another profile
                    logger.warning("Could not delete certificate %s: %s", name, e)


def parse_certificate(cert_pem: str) -> dict[str, Any]:
    """Parse certificate PEM and extract information.

    Args:
        cert_pem: Certificate in PEM format.

    Returns:
        Dictionary with certificate details.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Extract subject common name
    cn = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            cn = attr.value
            break

    # Extract SANs
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = [name.value for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    return {
        "common_name": cn,
        "sans": sans,
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
    }


def validate_key_matches_cert(cert_pem: str, key_pem: str) -> bool:
    """Validate that a private key matches a certificate.

    Args:
        cert_pem: Certificate in PEM format.
        key_pem: Private key in PEM format.

    Returns:
        True if the key matches the certificate.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)

    cert_public_key = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return cert_public_key == key_public_key

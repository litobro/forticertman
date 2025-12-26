"""acme.sh wrapper for certificate management."""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forticertman.config import AcmeConfig, CertificateConfig, CloudflareConfig

logger = logging.getLogger(__name__)

ACME_SH_INSTALL_URL = "https://get.acme.sh"


class AcmeError(Exception):
    """ACME operation error."""


@dataclass
class CertificateFiles:
    """Paths to certificate files."""

    cert: Path
    key: Path
    fullchain: Path
    ca: Path

    def exists(self) -> bool:
        """Check if all certificate files exist."""
        return all(p.exists() for p in [self.cert, self.key, self.fullchain])

    def read_cert(self) -> str:
        """Read the certificate file content."""
        return self.cert.read_text()

    def read_key(self) -> str:
        """Read the private key file content."""
        return self.key.read_text()

    def read_fullchain(self) -> str:
        """Read the full chain certificate content."""
        return self.fullchain.read_text()


class AcmeClient:
    """Wrapper for acme.sh certificate operations."""

    def __init__(
        self,
        acme_config: AcmeConfig,
        cloudflare_config: CloudflareConfig,
    ) -> None:
        self.acme_home = acme_config.acme_home
        self.ca = acme_config.ca
        self.email = acme_config.email
        self.eab_kid = acme_config.eab_kid
        self.eab_hmac_key = acme_config.eab_hmac_key
        self.cf_token = cloudflare_config.api_token
        self._acme_sh = self.acme_home / "acme.sh"

    def is_installed(self) -> bool:
        """Check if acme.sh is installed."""
        return self._acme_sh.exists()

    def install(self) -> None:
        """Install acme.sh."""
        if self.is_installed():
            logger.info("acme.sh is already installed at %s", self.acme_home)
            return

        logger.info("Installing acme.sh to %s", self.acme_home)
        try:
            result = subprocess.run(
                ["curl", "-fsSL", ACME_SH_INSTALL_URL],
                capture_output=True,
                text=True,
                check=True,
            )
            subprocess.run(
                ["sh", "-s", "--", "--install", "--home", str(self.acme_home)],
                input=result.stdout,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise AcmeError(f"Failed to install acme.sh: {e.stderr}") from e

        logger.info("acme.sh installed successfully")

    # Arguments that should be redacted in logs
    _SENSITIVE_ARGS = {"--eab-kid", "--eab-hmac-key"}

    def _redact_args_for_logging(self, args: list[str]) -> list[str]:
        """Redact sensitive arguments for safe logging."""
        redacted = []
        skip_next = False
        for arg in args:
            if skip_next:
                redacted.append("[REDACTED]")
                skip_next = False
            elif arg in self._SENSITIVE_ARGS:
                redacted.append(arg)
                skip_next = True
            else:
                redacted.append(arg)
        return redacted

    def _run_acme(
        self,
        args: list[str],
        env_extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run an acme.sh command."""
        if not self.is_installed():
            raise AcmeError("acme.sh is not installed. Run install() first.")

        cmd = [str(self._acme_sh)] + args
        env = os.environ.copy()
        env["HOME"] = str(self.acme_home.parent)
        if env_extra:
            env.update(env_extra)

        # Log with sensitive values redacted
        safe_cmd = [str(self._acme_sh)] + self._redact_args_for_logging(args)
        logger.debug("Running: %s", " ".join(safe_cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                env=env,
            )
            if result.stdout:
                logger.debug("stdout: %s", result.stdout)
            return result
        except subprocess.CalledProcessError as e:
            logger.error("acme.sh failed: %s", e.stderr)
            raise AcmeError(f"acme.sh command failed: {e.stderr}") from e

    def _get_ca_server(self) -> str:
        """Get the ACME server URL for the configured CA."""
        if self.ca == "zerossl":
            return "zerossl"
        return "letsencrypt"

    def register_account(self) -> None:
        """Register account with the CA (required for ZeroSSL)."""
        logger.info("Registering account with %s", self.ca)
        args = [
            "--register-account",
            "-m", self.email,
            "--server", self._get_ca_server(),
        ]
        if self.ca == "zerossl" and self.eab_kid and self.eab_hmac_key:
            args.extend([
                "--eab-kid", self.eab_kid,
                "--eab-hmac-key", self.eab_hmac_key,
            ])
        self._run_acme(args)
        logger.info("Account registered successfully")

    def issue_certificate(
        self,
        cert_config: CertificateConfig,
        force: bool = False,
    ) -> CertificateFiles:
        """Issue a new certificate using DNS-01 challenge via Cloudflare.

        Args:
            cert_config: Certificate configuration.
            force: Force renewal even if not due.

        Returns:
            Paths to the certificate files.
        """
        logger.info("Issuing certificate for %s", cert_config.name)

        # Build domain arguments
        domain_args: list[str] = []
        for domain in cert_config.domains:
            domain_args.extend(["-d", domain])

        args = [
            "--issue",
            "--dns", "dns_cf",
            "--server", self._get_ca_server(),
            "--keylength", cert_config.key_type,
            *domain_args,
        ]

        if force:
            args.append("--force")

        # Set Cloudflare API token
        env = {"CF_Token": self.cf_token}

        self._run_acme(args, env_extra=env)
        logger.info("Certificate issued successfully for %s", cert_config.name)

        return self.get_certificate_files(cert_config)

    def renew_certificate(
        self,
        cert_config: CertificateConfig,
        force: bool = False,
    ) -> CertificateFiles:
        """Renew a certificate.

        Args:
            cert_config: Certificate configuration.
            force: Force renewal even if not due.

        Returns:
            Paths to the certificate files.
        """
        logger.info("Renewing certificate for %s", cert_config.name)

        args = [
            "--renew",
            "-d", cert_config.primary_domain,
        ]

        if force:
            args.append("--force")

        env = {"CF_Token": self.cf_token}

        try:
            self._run_acme(args, env_extra=env)
            logger.info("Certificate renewed successfully for %s", cert_config.name)
        except AcmeError as e:
            if "is not a issued domain" in str(e):
                logger.warning("Certificate not found, issuing new one")
                return self.issue_certificate(cert_config, force=True)
            raise

        return self.get_certificate_files(cert_config)

    def renew_all(self, force: bool = False) -> None:
        """Renew all certificates that are due.

        Args:
            force: Force renewal even if not due.
        """
        logger.info("Renewing all certificates")
        args = ["--renew-all"]
        if force:
            args.append("--force")

        env = {"CF_Token": self.cf_token}
        self._run_acme(args, env_extra=env)
        logger.info("Renewal check completed")

    def get_certificate_files(self, cert_config: CertificateConfig) -> CertificateFiles:
        """Get paths to certificate files for a domain.

        Args:
            cert_config: Certificate configuration.

        Returns:
            Paths to the certificate files.
        """
        # acme.sh stores certs by primary domain
        primary = cert_config.primary_domain
        # Handle wildcard - acme.sh uses the domain without the *. prefix for directory
        if primary.startswith("*."):
            primary = primary[2:]

        cert_dir = self.acme_home / f"{primary}_ecc"
        if not cert_dir.exists():
            # Try non-ECC path for RSA keys
            cert_dir = self.acme_home / primary

        return CertificateFiles(
            cert=cert_dir / f"{primary}.cer",
            key=cert_dir / f"{primary}.key",
            fullchain=cert_dir / "fullchain.cer",
            ca=cert_dir / "ca.cer",
        )

    def list_certificates(self) -> list[dict[str, str]]:
        """List all managed certificates.

        Returns:
            List of certificate info dictionaries.
        """
        result = self._run_acme(["--list"])
        certs = []
        lines = result.stdout.strip().split("\n")

        # Skip header line
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                certs.append({
                    "domain": parts[0],
                    "key_length": parts[1],
                    "san_domains": parts[2] if len(parts) > 2 else "",
                    "created": parts[3] if len(parts) > 3 else "",
                })
        return certs

    def get_certificate_info(self, cert_config: CertificateConfig) -> dict[str, str] | None:
        """Get info about a specific certificate.

        Args:
            cert_config: Certificate configuration.

        Returns:
            Certificate info or None if not found.
        """
        certs = self.list_certificates()
        primary = cert_config.primary_domain
        for cert in certs:
            if cert["domain"] == primary:
                return cert
        return None

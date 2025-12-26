"""Configuration management for FortiCertMan."""

from __future__ import annotations

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Domain validation regex - allows wildcards, subdomains, and standard TLDs
DOMAIN_REGEX = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class ConfigError(Exception):
    """Configuration error."""


def _validate_domain(domain: str) -> bool:
    """Validate a domain name format."""
    return bool(DOMAIN_REGEX.match(domain))


@dataclass
class AcmeConfig:
    """ACME/certificate authority configuration."""

    ca: str  # "zerossl" or "letsencrypt"
    email: str
    eab_kid: str | None = None  # Required for ZeroSSL
    eab_hmac_key: str | None = None  # Required for ZeroSSL
    acme_home: Path = field(default_factory=lambda: Path.home() / ".acme.sh")

    def __post_init__(self) -> None:
        if self.ca not in ("zerossl", "letsencrypt"):
            raise ConfigError(f"Invalid CA: {self.ca}. Must be 'zerossl' or 'letsencrypt'")
        if self.ca == "zerossl" and (not self.eab_kid or not self.eab_hmac_key):
            raise ConfigError("ZeroSSL requires eab_kid and eab_hmac_key")


@dataclass
class CloudflareConfig:
    """Cloudflare DNS API configuration."""

    api_token: str

    def __post_init__(self) -> None:
        if not self.api_token:
            raise ConfigError("Cloudflare api_token is required")


@dataclass
class FortigateConfig:
    """Fortigate firewall configuration."""

    host: str
    api_token: str
    port: int = 443
    verify_ssl: bool = True
    timeout: int = 30

    def __post_init__(self) -> None:
        if not self.host:
            raise ConfigError("Fortigate host is required")
        if not self.api_token:
            raise ConfigError("Fortigate api_token is required")
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"Invalid port: {self.port}. Must be 1-65535")

    @property
    def base_url(self) -> str:
        """Get the base URL for API requests."""
        return f"https://{self.host}:{self.port}"


@dataclass
class CertificateDeployment:
    """Certificate deployment target configuration."""

    ssl_inspection: bool = False
    profile: str | None = None  # SSL inspection profile name
    vip: str | None = None  # VIP name for SSL offloading

    def __post_init__(self) -> None:
        if self.ssl_inspection and not self.profile:
            raise ConfigError("ssl_inspection requires a profile name")


@dataclass
class CertificateConfig:
    """Individual certificate configuration."""

    name: str
    domains: list[str]
    deploy_to: list[CertificateDeployment] = field(default_factory=list)
    key_type: str = "ec-256"  # ec-256, ec-384, rsa-2048, rsa-4096

    def __post_init__(self) -> None:
        if not self.name:
            raise ConfigError("Certificate name is required")
        if not self.domains:
            raise ConfigError(f"Certificate '{self.name}' requires at least one domain")
        if self.key_type not in ("ec-256", "ec-384", "rsa-2048", "rsa-4096"):
            raise ConfigError(f"Invalid key_type: {self.key_type}")
        # Validate domain names
        for domain in self.domains:
            if not _validate_domain(domain):
                raise ConfigError(
                    f"Invalid domain '{domain}' in certificate '{self.name}'. "
                    "Must be a valid domain name (e.g., 'example.com' or '*.example.com')"
                )

    @property
    def primary_domain(self) -> str:
        """Get the primary (first) domain."""
        return self.domains[0]

    @property
    def is_wildcard(self) -> bool:
        """Check if any domain is a wildcard."""
        return any(d.startswith("*.") for d in self.domains)


@dataclass
class Config:
    """Main configuration container."""

    acme: AcmeConfig
    cloudflare: CloudflareConfig
    fortigate: FortigateConfig
    certificates: list[CertificateConfig]
    data_dir: Path = field(default_factory=lambda: Path("/var/lib/forticertman"))
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if not self.certificates:
            raise ConfigError("At least one certificate must be configured")


def _parse_deployment(data: dict[str, Any]) -> CertificateDeployment:
    """Parse a deployment target from config data."""
    return CertificateDeployment(
        ssl_inspection=data.get("ssl_inspection", False),
        profile=data.get("profile"),
        vip=data.get("vip"),
    )


def _parse_certificate(data: dict[str, Any]) -> CertificateConfig:
    """Parse a certificate configuration from config data."""
    deploy_to = [_parse_deployment(d) for d in data.get("deploy_to", [])]
    return CertificateConfig(
        name=data["name"],
        domains=data["domains"],
        deploy_to=deploy_to,
        key_type=data.get("key_type", "ec-256"),
    )


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand environment variables in config values."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_vars(v) for v in value]
    return value


def _check_file_permissions(path: Path) -> None:
    """Warn if config file has insecure permissions."""
    try:
        file_stat = path.stat()
        mode = file_stat.st_mode
        # Check if group or others have any permissions
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            logger.warning(
                "Config file %s has insecure permissions (mode %o). "
                "Consider running: chmod 600 %s",
                path,
                stat.S_IMODE(mode),
                path,
            )
    except OSError:
        pass  # Ignore permission check errors


def load_config(config_path: Path | str) -> Config:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to the configuration file.

    Returns:
        Parsed configuration object.

    Raises:
        ConfigError: If the configuration is invalid.
        FileNotFoundError: If the config file doesn't exist.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    # Warn about insecure file permissions
    _check_file_permissions(config_path)

    with open(config_path) as f:
        raw_config = yaml.safe_load(f)

    if not raw_config:
        raise ConfigError("Configuration file is empty")

    # Expand environment variables
    raw_config = _expand_env_vars(raw_config)

    # Parse sections
    acme_data = raw_config.get("acme", {})
    acme = AcmeConfig(
        ca=acme_data.get("ca", "zerossl"),
        email=acme_data.get("email", ""),
        eab_kid=acme_data.get("eab_kid"),
        eab_hmac_key=acme_data.get("eab_hmac_key"),
        acme_home=Path(acme_data.get("acme_home", Path.home() / ".acme.sh")),
    )

    cf_data = raw_config.get("cloudflare", {})
    cloudflare = CloudflareConfig(api_token=cf_data.get("api_token", ""))

    fg_data = raw_config.get("fortigate", {})
    fortigate = FortigateConfig(
        host=fg_data.get("host", ""),
        api_token=fg_data.get("api_token", ""),
        port=fg_data.get("port", 443),
        verify_ssl=fg_data.get("verify_ssl", False),
        timeout=fg_data.get("timeout", 30),
    )

    certificates = [_parse_certificate(c) for c in raw_config.get("certificates", [])]

    data_dir = Path(raw_config.get("data_dir", "/var/lib/forticertman"))
    log_level = raw_config.get("log_level", "INFO")

    return Config(
        acme=acme,
        cloudflare=cloudflare,
        fortigate=fortigate,
        certificates=certificates,
        data_dir=data_dir,
        log_level=log_level,
    )


def get_default_config_paths() -> list[Path]:
    """Get list of default configuration file paths to search."""
    return [
        Path("config.yaml"),
        Path("config.yml"),
        Path("/etc/forticertman/config.yaml"),
        Path("/etc/forticertman/config.yml"),
        Path.home() / ".config" / "forticertman" / "config.yaml",
    ]


def find_config() -> Path | None:
    """Find the first existing configuration file from default paths."""
    for path in get_default_config_paths():
        if path.exists():
            return path
    return None

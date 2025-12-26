"""Daemon functionality for automated certificate renewal."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from forticertman.acme import AcmeClient, AcmeError
from forticertman.config import Config, ConfigError, find_config, load_config
from forticertman.fortigate import FortigateClient, FortigateError

logger = logging.getLogger("forticertman.daemon")


def setup_logging(log_level: str = "INFO") -> None:
    """Configure logging for daemon mode."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def run_sync(config_path: Path | str | None = None, force: bool = False) -> int:
    """Run certificate sync operation.

    This is the main function called by systemd timer. It:
    1. Loads configuration
    2. Renews any certificates that are due
    3. Pushes all certificates to Fortigate

    Args:
        config_path: Path to configuration file (optional).
        force: Force renewal even if not due.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Load configuration
    try:
        if config_path:
            config = load_config(Path(config_path))
        else:
            found_path = find_config()
            if not found_path:
                logger.error("No configuration file found")
                return 1
            config = load_config(found_path)
    except (FileNotFoundError, ConfigError) as e:
        logger.error("Configuration error: %s", e)
        return 1

    setup_logging(config.log_level)
    logger.info("Starting certificate sync")

    # Initialize clients
    acme = AcmeClient(config.acme, config.cloudflare)
    fg = FortigateClient(config.fortigate)

    # Check acme.sh is installed
    if not acme.is_installed():
        logger.error("acme.sh is not installed")
        return 1

    # Test Fortigate connection
    if not fg.test_connection():
        logger.error("Cannot connect to Fortigate at %s", config.fortigate.host)
        return 1

    # Renew certificates
    logger.info("Checking for certificate renewals...")
    try:
        acme.renew_all(force=force)
    except AcmeError as e:
        logger.error("Renewal failed: %s", e)
        return 1

    # Push certificates to Fortigate
    logger.info("Pushing certificates to Fortigate...")
    errors = []

    for cert_config in config.certificates:
        try:
            cert_files = acme.get_certificate_files(cert_config)
            if not cert_files.exists():
                logger.warning(
                    "Certificate files for '%s' not found, skipping",
                    cert_config.name,
                )
                continue

            cert_pem = cert_files.read_fullchain()
            key_pem = cert_files.read_key()

            if cert_config.deploy_to:
                fg.deploy_certificate(
                    cert_config.name,
                    cert_pem,
                    key_pem,
                    cert_config.deploy_to,
                )
                logger.info("Deployed certificate: %s", cert_config.name)
            else:
                logger.debug(
                    "Certificate '%s' has no deployment targets, skipping",
                    cert_config.name,
                )

        except (AcmeError, FortigateError) as e:
            error_msg = f"{cert_config.name}: {e}"
            errors.append(error_msg)
            logger.error("Failed to deploy '%s': %s", cert_config.name, e)

    if errors:
        logger.error("Sync completed with %d error(s)", len(errors))
        return 1

    logger.info("Certificate sync completed successfully")
    return 0


def main() -> None:
    """Entry point for daemon mode."""
    import argparse

    parser = argparse.ArgumentParser(
        description="FortiCertMan daemon - automated certificate sync"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force renewal even if not due",
    )
    args = parser.parse_args()

    sys.exit(run_sync(args.config, args.force))


if __name__ == "__main__":
    main()

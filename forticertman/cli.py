"""Command-line interface for FortiCertMan."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from forticertman import __version__
from forticertman.acme import AcmeClient, AcmeError
from forticertman.config import Config, ConfigError, find_config, load_config
from forticertman.fortigate import FortigateClient, FortigateError, parse_certificate

logger = logging.getLogger("forticertman")


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_config_or_exit(config_path: str | None) -> Config:
    """Load configuration or exit with error."""
    try:
        if config_path:
            path = Path(config_path)
        else:
            path = find_config()
            if not path:
                click.echo("Error: No configuration file found.", err=True)
                click.echo("Searched locations:", err=True)
                from forticertman.config import get_default_config_paths
                for p in get_default_config_paths():
                    click.echo(f"  - {p}", err=True)
                click.echo("\nCreate a config.yaml or specify path with -c/--config", err=True)
                sys.exit(1)
        return load_config(path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConfigError as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(1)


@click.group()
@click.version_option(version=__version__, prog_name="forticertman")
@click.option("-c", "--config", "config_path", help="Path to configuration file")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def main(ctx: click.Context, config_path: str | None, verbose: bool) -> None:
    """FortiCertMan - ACME certificate manager for Fortigate firewalls.

    Manages SSL certificates using acme.sh and deploys them to Fortigate
    for SSL inspection and SSL offloading.
    """
    setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["verbose"] = verbose


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show status of certificates and connections."""
    config = load_config_or_exit(ctx.obj["config_path"])

    click.echo("=== FortiCertMan Status ===\n")

    # Test Fortigate connection
    click.echo("Fortigate Connection:")
    fg = FortigateClient(config.fortigate)
    try:
        if fg.test_connection():
            status_info = fg.get_system_status()
            click.echo(f"  Host: {config.fortigate.host}:{config.fortigate.port}")
            click.echo(f"  Status: Connected")
            click.echo(f"  Hostname: {status_info.get('hostname', 'N/A')}")
            click.echo(f"  Version: {status_info.get('version', 'N/A')}")
        else:
            click.echo(f"  Status: Failed to connect")
    except FortigateError as e:
        click.echo(f"  Status: Error - {e}")

    click.echo()

    # Check acme.sh
    acme = AcmeClient(config.acme, config.cloudflare)
    click.echo("ACME Client:")
    click.echo(f"  Installed: {'Yes' if acme.is_installed() else 'No'}")
    click.echo(f"  CA: {config.acme.ca}")
    click.echo(f"  Home: {config.acme.acme_home}")

    if acme.is_installed():
        click.echo()
        click.echo("Managed Certificates:")
        try:
            certs = acme.list_certificates()
            if certs:
                for cert in certs:
                    click.echo(f"  - {cert['domain']} ({cert['key_length']})")
            else:
                click.echo("  No certificates issued yet")
        except AcmeError as e:
            click.echo(f"  Error listing certificates: {e}")

    click.echo()
    click.echo("Configured Certificates:")
    for cert in config.certificates:
        click.echo(f"  - {cert.name}")
        click.echo(f"    Domains: {', '.join(cert.domains)}")
        if cert.deploy_to:
            for deploy in cert.deploy_to:
                if deploy.ssl_inspection:
                    click.echo(f"    Deploy: SSL Inspection profile '{deploy.profile}'")
                if deploy.vip:
                    click.echo(f"    Deploy: VIP '{deploy.vip}'")


@main.command()
@click.pass_context
def install(ctx: click.Context) -> None:
    """Install acme.sh and register account."""
    config = load_config_or_exit(ctx.obj["config_path"])

    acme = AcmeClient(config.acme, config.cloudflare)

    try:
        click.echo("Installing acme.sh...")
        acme.install()

        click.echo("Registering account...")
        acme.register_account()

        click.echo("Installation complete!")
    except AcmeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option("--name", "-n", help="Certificate name to issue (from config)")
@click.option("--all", "issue_all", is_flag=True, help="Issue all configured certificates")
@click.option("--force", "-f", is_flag=True, help="Force issue even if certificate exists")
@click.pass_context
def issue(
    ctx: click.Context,
    name: str | None,
    issue_all: bool,
    force: bool,
) -> None:
    """Issue new certificates."""
    config = load_config_or_exit(ctx.obj["config_path"])
    acme = AcmeClient(config.acme, config.cloudflare)

    if not acme.is_installed():
        click.echo("Error: acme.sh is not installed. Run 'forticertman install' first.", err=True)
        sys.exit(1)

    # Determine which certificates to issue
    if issue_all:
        certs_to_issue = config.certificates
    elif name:
        certs_to_issue = [c for c in config.certificates if c.name == name]
        if not certs_to_issue:
            click.echo(f"Error: Certificate '{name}' not found in configuration.", err=True)
            click.echo("Available certificates:", err=True)
            for c in config.certificates:
                click.echo(f"  - {c.name}", err=True)
            sys.exit(1)
    else:
        click.echo("Error: Specify --name or --all", err=True)
        sys.exit(1)

    for cert_config in certs_to_issue:
        try:
            click.echo(f"Issuing certificate: {cert_config.name}")
            click.echo(f"  Domains: {', '.join(cert_config.domains)}")
            acme.issue_certificate(cert_config, force=force)
            click.echo(f"  Success!")
        except AcmeError as e:
            click.echo(f"  Error: {e}", err=True)
            if not issue_all:
                sys.exit(1)


@main.command()
@click.option("--force", "-f", is_flag=True, help="Force renewal even if not due")
@click.pass_context
def renew(ctx: click.Context, force: bool) -> None:
    """Renew certificates that are due."""
    config = load_config_or_exit(ctx.obj["config_path"])
    acme = AcmeClient(config.acme, config.cloudflare)

    if not acme.is_installed():
        click.echo("Error: acme.sh is not installed. Run 'forticertman install' first.", err=True)
        sys.exit(1)

    try:
        click.echo("Checking for certificates to renew...")
        acme.renew_all(force=force)
        click.echo("Renewal check complete.")
    except AcmeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option("--name", "-n", help="Certificate name to push (from config)")
@click.option("--all", "push_all", is_flag=True, help="Push all configured certificates")
@click.pass_context
def push(ctx: click.Context, name: str | None, push_all: bool) -> None:
    """Push certificates to Fortigate."""
    config = load_config_or_exit(ctx.obj["config_path"])
    acme = AcmeClient(config.acme, config.cloudflare)
    fg = FortigateClient(config.fortigate)

    if not acme.is_installed():
        click.echo("Error: acme.sh is not installed. Run 'forticertman install' first.", err=True)
        sys.exit(1)

    # Test Fortigate connection
    if not fg.test_connection():
        click.echo("Error: Cannot connect to Fortigate.", err=True)
        sys.exit(1)

    # Determine which certificates to push
    if push_all:
        certs_to_push = config.certificates
    elif name:
        certs_to_push = [c for c in config.certificates if c.name == name]
        if not certs_to_push:
            click.echo(f"Error: Certificate '{name}' not found in configuration.", err=True)
            sys.exit(1)
    else:
        click.echo("Error: Specify --name or --all", err=True)
        sys.exit(1)

    for cert_config in certs_to_push:
        try:
            click.echo(f"Pushing certificate: {cert_config.name}")

            # Get certificate files
            cert_files = acme.get_certificate_files(cert_config)
            if not cert_files.exists():
                click.echo(f"  Error: Certificate files not found. Issue certificate first.")
                continue

            # Read certificate and key
            cert_pem = cert_files.read_fullchain()
            key_pem = cert_files.read_key()

            # Show certificate info
            cert_info = parse_certificate(cert_pem)
            click.echo(f"  CN: {cert_info['common_name']}")
            click.echo(f"  Expires: {cert_info['not_after']}")

            # Deploy to Fortigate
            if cert_config.deploy_to:
                fg.deploy_certificate(
                    cert_config.name,
                    cert_pem,
                    key_pem,
                    cert_config.deploy_to,
                )
                click.echo(f"  Deployed to Fortigate")
            else:
                # Just upload without binding to profiles
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                fg.upload_certificate(f"{cert_config.name}_{timestamp}", cert_pem, key_pem)
                click.echo(f"  Uploaded to Fortigate (no deployment targets configured)")

        except (AcmeError, FortigateError) as e:
            click.echo(f"  Error: {e}", err=True)
            if not push_all:
                sys.exit(1)


@main.command()
@click.option("--force", "-f", is_flag=True, help="Force renewal even if not due")
@click.pass_context
def sync(ctx: click.Context, force: bool) -> None:
    """Renew certificates and push to Fortigate.

    This is the main command for automated renewal - it renews any
    certificates that are due and pushes them to the Fortigate.
    """
    config = load_config_or_exit(ctx.obj["config_path"])
    acme = AcmeClient(config.acme, config.cloudflare)
    fg = FortigateClient(config.fortigate)

    if not acme.is_installed():
        click.echo("Error: acme.sh is not installed. Run 'forticertman install' first.", err=True)
        sys.exit(1)

    # Test Fortigate connection
    if not fg.test_connection():
        click.echo("Error: Cannot connect to Fortigate.", err=True)
        sys.exit(1)

    # Renew all certificates
    click.echo("Checking for certificates to renew...")
    try:
        acme.renew_all(force=force)
    except AcmeError as e:
        click.echo(f"Error during renewal: {e}", err=True)
        sys.exit(1)

    # Push all certificates to Fortigate
    click.echo("Pushing certificates to Fortigate...")
    errors = []
    for cert_config in config.certificates:
        try:
            cert_files = acme.get_certificate_files(cert_config)
            if not cert_files.exists():
                logger.warning("Certificate %s not found, skipping", cert_config.name)
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
                click.echo(f"  Deployed: {cert_config.name}")

        except (AcmeError, FortigateError) as e:
            errors.append(f"{cert_config.name}: {e}")
            logger.error("Failed to deploy %s: %s", cert_config.name, e)

    if errors:
        click.echo("\nErrors occurred:", err=True)
        for error in errors:
            click.echo(f"  - {error}", err=True)
        sys.exit(1)

    click.echo("Sync complete!")


@main.command("list-certs")
@click.pass_context
def list_certs(ctx: click.Context) -> None:
    """List certificates on Fortigate."""
    config = load_config_or_exit(ctx.obj["config_path"])
    fg = FortigateClient(config.fortigate)

    if not fg.test_connection():
        click.echo("Error: Cannot connect to Fortigate.", err=True)
        sys.exit(1)

    certs = fg.list_certificates()
    if not certs:
        click.echo("No certificates found on Fortigate.")
        return

    click.echo("Certificates on Fortigate:")
    for cert in certs:
        name = cert.get("name", "N/A")
        subject = cert.get("subject", "N/A")
        click.echo(f"  - {name}")
        click.echo(f"    Subject: {subject}")


if __name__ == "__main__":
    main()

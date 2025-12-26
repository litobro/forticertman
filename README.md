# FortiCertMan

ACME certificate manager for Fortigate firewalls. Automates SSL certificate provisioning and renewal using acme.sh, then pushes certificates to Fortigate via REST API for SSL inspection and SSL offloading.

## Features

- Uses acme.sh for certificate management (battle-tested, widely used)
- DNS-01 validation via Cloudflare API (supports wildcards)
- Supports ZeroSSL and Let's Encrypt certificate authorities
- Pushes certificates to Fortigate via REST API
- Updates SSL inspection profiles and VIPs automatically
- Automated daily renewal via systemd timer
- Handles certificate rotation with automatic cleanup of old certs

## Requirements

- Debian or Ubuntu (tested on LXC containers)
- Python 3.10+
- Cloudflare-managed DNS for your domains
- Fortigate with REST API access enabled

## Installation

### Quick Install

```bash
git clone https://github.com/litobro/forticertman
cd forticertman
sudo ./install.sh
```

### Manual Install

```bash
# Install dependencies
sudo apt install python3 python3-pip python3-venv curl socat

# Create virtual environment
python3 -m venv /opt/forticertman/venv
source /opt/forticertman/venv/bin/activate

# Install package
pip install .

# Create config directory
sudo mkdir -p /etc/forticertman
sudo cp config.example.yaml /etc/forticertman/config.yaml
sudo chmod 600 /etc/forticertman/config.yaml

# Install systemd units
sudo cp systemd/forticertman.service /etc/systemd/system/
sudo cp systemd/forticertman.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

## Configuration

Edit `/etc/forticertman/config.yaml`:

```yaml
acme:
  ca: zerossl
  email: admin@example.com
  eab_kid: "your_eab_kid"
  eab_hmac_key: "your_eab_hmac_key"

cloudflare:
  api_token: "your_cloudflare_api_token"

fortigate:
  host: "192.168.1.1"
  port: 443
  api_token: "your_fortigate_api_token"
  verify_ssl: false

certificates:
  - name: "wildcard-example-com"
    domains:
      - "*.example.com"
      - "example.com"
    deploy_to:
      - ssl_inspection: true
        profile: "deep-inspection"

  - name: "webapp"
    domains:
      - "app.example.com"
    deploy_to:
      - vip: "webapp-vip"
```

### Getting API Credentials

**ZeroSSL EAB Credentials:**
1. Create account at https://zerossl.com
2. Go to Developer section
3. Generate EAB credentials for ACME

**Cloudflare API Token:**
1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Create token with `Zone.DNS:Edit` permission for your zones

**Fortigate API Token:**
1. Go to System > Administrators
2. Create New > REST API Admin
3. Set permissions:
   - System > Configuration: Read/Write
   - VPN: Read/Write
4. If using VDOMs, set scope to "global"

## Usage

### Initial Setup

```bash
# Install acme.sh and register with CA
forticertman install

# Issue all configured certificates
forticertman issue --all

# Push certificates to Fortigate
forticertman push --all

# Enable automatic renewal
sudo systemctl enable --now forticertman.timer
```

### Commands

```bash
# Show status of certificates and connections
forticertman status

# Issue a specific certificate
forticertman issue --name wildcard-example-com

# Issue all certificates
forticertman issue --all

# Force renewal (even if not due)
forticertman renew --force

# Push certificates to Fortigate
forticertman push --all

# Renew and push in one command (used by systemd timer)
forticertman sync

# List certificates on Fortigate
forticertman list-certs
```

### Options

```
-c, --config PATH    Path to configuration file
-v, --verbose        Enable debug output
--help               Show help message
```

## Automation

The systemd timer runs daily at 3 AM (with up to 1 hour random delay) to check for renewals:

```bash
# Enable automatic renewal
sudo systemctl enable --now forticertman.timer

# Check timer status
systemctl status forticertman.timer

# View logs
journalctl -u forticertman.service

# Run manually
sudo systemctl start forticertman.service
```

## Certificate Deployment

### SSL Inspection

For deep packet inspection, configure your certificate to deploy to an SSL inspection profile:

```yaml
certificates:
  - name: "inspection-cert"
    domains:
      - "*.example.com"
    deploy_to:
      - ssl_inspection: true
        profile: "deep-inspection"
```

The certificate will be set as the `server-cert` on the specified SSL/SSH inspection profile.

### SSL Offloading (VIP)

For SSL offloading on a Virtual IP:

```yaml
certificates:
  - name: "webapp-cert"
    domains:
      - "app.example.com"
    deploy_to:
      - vip: "webapp-vip"
```

### Multiple Deployments

A single certificate can be deployed to multiple targets:

```yaml
certificates:
  - name: "multi-use-cert"
    domains:
      - "*.example.com"
    deploy_to:
      - ssl_inspection: true
        profile: "deep-inspection"
      - vip: "webapp-vip"
      - vip: "api-vip"
```

## Key Types

Supported key types:

- `ec-256` (default) - ECDSA P-256, good balance of security and performance
- `ec-384` - ECDSA P-384, higher security
- `rsa-2048` - RSA 2048-bit, for compatibility with older clients
- `rsa-4096` - RSA 4096-bit, maximum RSA security

```yaml
certificates:
  - name: "legacy-compatible"
    domains:
      - "legacy.example.com"
    key_type: rsa-2048
```

## Environment Variables

Sensitive values can be set via environment variables:

```yaml
cloudflare:
  api_token: "${CF_API_TOKEN}"

fortigate:
  api_token: "${FG_API_TOKEN}"
```

## Troubleshooting

### Connection refused to Fortigate

- Verify the host and port are correct
- Ensure REST API is enabled on the Fortigate
- Check that your API token has sufficient permissions
- If using HTTPS on a non-standard port, update the `port` setting

### SSL certificate verify failed

Set `verify_ssl: false` in the fortigate config if the Fortigate is using a self-signed certificate.

### Certificate not renewing

acme.sh only renews certificates within 30 days of expiry. Use `--force` to renew early:

```bash
forticertman renew --force
```

### DNS validation failing

- Verify your Cloudflare API token has `Zone.DNS:Edit` permission
- Ensure the token covers the zone for your domain
- Check that the domain is actually using Cloudflare DNS

### View debug output

```bash
forticertman -v status
forticertman -v issue --all
```

## File Locations

| Path | Description |
|------|-------------|
| `/etc/forticertman/config.yaml` | Configuration file |
| `/var/lib/forticertman/` | Data directory |
| `/root/.acme.sh/` | acme.sh installation and certificates |
| `/etc/systemd/system/forticertman.timer` | Systemd timer unit |
| `/etc/systemd/system/forticertman.service` | Systemd service unit |

## License

MIT License. See [LICENSE](LICENSE) for details.

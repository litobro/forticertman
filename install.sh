#!/bin/bash
#
# FortiCertMan Installation Script
# For Debian/Ubuntu LXC containers
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
else
    log_error "Cannot detect OS"
    exit 1
fi

if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
    log_warn "This script is designed for Debian/Ubuntu. Proceeding anyway..."
fi

log_info "Installing FortiCertMan on $PRETTY_NAME"

# Install system dependencies
log_info "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    socat \
    cron

# Create installation directory
INSTALL_DIR="/opt/forticertman"
log_info "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Create virtual environment
log_info "Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install forticertman
log_info "Installing forticertman..."
if [[ -f "pyproject.toml" ]]; then
    # Install from local directory (development)
    # Use --force-reinstall to ensure updates are applied
    pip install -q --force-reinstall .
else
    # Install from PyPI (production)
    pip install -q --upgrade forticertman
fi

# Create symlink to binary
log_info "Creating CLI symlink..."
ln -sf "$INSTALL_DIR/venv/bin/forticertman" /usr/local/bin/forticertman

# Create configuration directory
CONFIG_DIR="/etc/forticertman"
log_info "Creating configuration directory: $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Copy example configuration if it doesn't exist
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    if [[ -f "config.example.yaml" ]]; then
        cp config.example.yaml "$CONFIG_DIR/config.yaml"
        chmod 600 "$CONFIG_DIR/config.yaml"
        log_info "Example configuration copied to $CONFIG_DIR/config.yaml"
    else
        log_warn "No example configuration found. Create $CONFIG_DIR/config.yaml manually."
    fi
else
    log_info "Configuration file already exists, skipping..."
fi

# Create data directory
DATA_DIR="/var/lib/forticertman"
log_info "Creating data directory: $DATA_DIR"
mkdir -p "$DATA_DIR"

# Install systemd units
log_info "Installing systemd units..."
if [[ -d "systemd" ]]; then
    cp systemd/forticertman.service /etc/systemd/system/
    cp systemd/forticertman.timer /etc/systemd/system/
else
    # Download from repo or create inline
    cat > /etc/systemd/system/forticertman.service << 'EOF'
[Unit]
Description=FortiCertMan - ACME certificate sync for Fortigate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/forticertman sync
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/root/.acme.sh
ReadWritePaths=/var/lib/forticertman

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/forticertman.timer << 'EOF'
[Unit]
Description=Daily certificate renewal check for FortiCertMan

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
fi

# Reload systemd
systemctl daemon-reload

log_info "Installation complete!"
echo ""
echo "========================================="
echo "  FortiCertMan Installation Complete"
echo "========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Edit the configuration file:"
echo "   nano $CONFIG_DIR/config.yaml"
echo ""
echo "2. Install acme.sh and register account:"
echo "   forticertman install"
echo ""
echo "3. Issue certificates:"
echo "   forticertman issue --all"
echo ""
echo "4. Push certificates to Fortigate:"
echo "   forticertman push --all"
echo ""
echo "5. Enable automatic renewal:"
echo "   systemctl enable --now forticertman.timer"
echo ""
echo "6. Check status:"
echo "   forticertman status"
echo "   systemctl status forticertman.timer"
echo ""

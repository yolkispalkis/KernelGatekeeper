# deploy/install.sh
#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root"
    exit 1
fi

SERVICE_BIN="kernelgatekeeper-service"
CLIENT_BIN="kernelgatekeeper-client"
CONFIG_DIR="/etc/kernelgatekeeper"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SYSTEMD_SYSTEM_DIR="/etc/systemd/system"
SYSTEMD_USER_DIR="/usr/lib/systemd/user" # Install user unit system-wide
SERVICE_FILE="kernelgatekeeper.service"
CLIENT_SERVICE_FILE="kernelgatekeeper-client.service"
LOG_DIR="/var/log"
LOG_FILE_PATH="/var/log/kernelgatekeeper.log"
BIN_DIR="bin"
DEPLOY_DIR="deploy"

echo "Starting KernelGatekeeper Installation (SockOps Model)..."

echo "Creating directories..."
mkdir -p "$CONFIG_DIR" "$SYSTEMD_SYSTEM_DIR" "$SYSTEMD_USER_DIR" "$LOG_DIR"

echo "Installing configuration file..."
if [ -f "config.yaml" ]; then
    if [ ! -f "$CONFIG_FILE" ]; then
        install -m 640 "config.yaml" "$CONFIG_FILE"
        # Consider chgrp root:somegroup "$CONFIG_FILE"
    else
        echo "Config file $CONFIG_FILE exists, skipping."
    fi
else
    echo "Warning: Default config.yaml not found."
fi

echo "Installing binary files..."
if [ ! -f "$BIN_DIR/$SERVICE_BIN" ] || [ ! -f "$BIN_DIR/$CLIENT_BIN" ]; then
    echo "Error: Binaries not found in $BIN_DIR/. Run 'make all' first."
    exit 1
fi
install -m 755 "$BIN_DIR/$SERVICE_BIN" /usr/local/bin/
install -m 755 "$BIN_DIR/$CLIENT_BIN" /usr/local/bin/

echo "Installing systemd service files..."
if [ ! -f "$DEPLOY_DIR/$SERVICE_FILE" ] || [ ! -f "$DEPLOY_DIR/$CLIENT_SERVICE_FILE" ]; then
    echo "Error: Systemd service files not found in $DEPLOY_DIR/."
    exit 1
fi
install -m 644 "$DEPLOY_DIR/$SERVICE_FILE" "$SYSTEMD_SYSTEM_DIR/"
install -m 644 "$DEPLOY_DIR/$CLIENT_SERVICE_FILE" "$SYSTEMD_USER_DIR/"

echo "Setting up log file $LOG_FILE_PATH..."
touch "$LOG_FILE_PATH"
chmod 640 "$LOG_FILE_PATH"
# Consider chown root:adm "$LOG_FILE_PATH"

echo "----------------------------------------"
echo "KernelGatekeeper Installation Complete!"
echo "----------------------------------------"
echo "IMPORTANT: This model requires Linux Kernel >= 5.6 and cgroup v2 enabled."
echo "           Ensure '/sys/fs/cgroup' is mounted with type cgroup2."
echo ""
echo "What's next?"
echo "1. Review the configuration file: $CONFIG_FILE"
echo "2. Reload systemd and enable the *system* service:"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl enable --now $SERVICE_FILE"
echo "3. As the target user, reload systemd and enable the *user* service:"
echo "   systemctl --user daemon-reload"
echo "   systemctl --user enable --now $CLIENT_SERVICE_FILE"
echo "4. Check service status:"
echo "   sudo systemctl status $SERVICE_FILE"
echo "5. Check client status (as user):"
echo "   systemctl --user status $CLIENT_SERVICE_FILE"
echo "6. Follow service logs:"
echo "   sudo journalctl -u $SERVICE_FILE -f"
echo "   or: sudo tail -f $LOG_FILE_PATH"
echo "7. Follow client logs (as user):"
echo "   journalctl --user -u $CLIENT_SERVICE_FILE -f"

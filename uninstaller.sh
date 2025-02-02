#!/bin/bash
# uninstaller.sh - Removes all traces of Zipline from the server

set -e

# Function to handle errors
handle_error() {
    echo "Error: $1"
    exit 1
}

echo "Starting Zipline uninstallation..."

# 1. Stop and disable the systemd service
SERVICE_NAME="zipline"
echo "Stopping Zipline service..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl stop "$SERVICE_NAME" || handle_error "Failed to stop Zipline service"
fi

echo "Disabling Zipline service..."
systemctl disable "$SERVICE_NAME" || echo "Service may already be disabled."

# 2. Remove the systemd service file
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE" || handle_error "Failed to remove service file $SERVICE_FILE"
    echo "Removed systemd service file: $SERVICE_FILE"
fi

# Reload systemd daemon to pick up the changes
systemctl daemon-reload || echo "Warning: Failed to reload systemd daemon."
systemctl reset-failed || echo "Warning: Failed to reset systemd failed state."

# 3. Remove the installation directory
INSTALL_DIR="/usr/local/zipline"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR" || handle_error "Failed to remove installation directory $INSTALL_DIR"
    echo "Removed installation directory: $INSTALL_DIR"
fi

# 4. Remove firewall rules for port 2000 (if present)
PORT=2000

# For iptables
if command -v iptables >/dev/null 2>&1; then
    echo "Removing iptables rule for TCP port $PORT (if exists)..."
    iptables -D INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || echo "iptables rule not found or already removed."
    
    # Save changes (RedHat/CentOS)
    if [ -f /etc/redhat-release ]; then
        service iptables save || echo "Warning: Failed to save iptables rules."
    # Save changes (Debian/Ubuntu)
    elif [ -f /etc/debian_version ]; then
        iptables-save > /etc/iptables/rules.v4 || echo "Warning: Failed to save iptables rules."
    fi
fi

# For firewalld
if command -v firewall-cmd >/dev/null 2>&1; then
    echo "Removing firewalld rule for TCP port $PORT (if exists)..."
    firewall-cmd --permanent --remove-port=${PORT}/tcp || echo "firewalld rule not found or already removed."
    firewall-cmd --reload || echo "Warning: Failed to reload firewalld."
fi

# For UFW
if command -v ufw >/dev/null 2>&1; then
    echo "Removing UFW rule for TCP port $PORT (if exists)..."
    ufw delete allow ${PORT}/tcp || echo "ufw rule not found or already removed."
    ufw reload || echo "Warning: Failed to reload UFW."
fi

# 5. Remove any log files created by Zipline (optional)
LOG_FILE1="/var/log/zipline-backup.log"
LOG_FILE2="/var/log/wp_db_import.log"

if [ -f "$LOG_FILE1" ]; then
    echo "Removing log file: $LOG_FILE1"
    rm -f "$LOG_FILE1" || echo "Warning: Failed to remove $LOG_FILE1"
fi

if [ -f "$LOG_FILE2" ]; then
    echo "Removing log file: $LOG_FILE2"
    rm -f "$LOG_FILE2" || echo "Warning: Failed to remove $LOG_FILE2"
fi

echo "Zipline has been successfully uninstalled from the server."
exit 0

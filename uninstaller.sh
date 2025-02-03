#!/bin/bash

# Function to handle errors
handle_error() {
    echo "Error: $1"
    exit 1
}

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Variables
INSTALL_DIR="/usr/local/zipline"
SERVICE_NAME="zipline"
LOG_FILE="/var/log/zipline-backup.log"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   handle_error "This script must be run as root"
fi

log_message "Starting Zipline uninstallation..."

# Stop and disable the service
log_message "Stopping and disabling Zipline service..."
systemctl stop "$SERVICE_NAME" 2>/dev/null
systemctl disable "$SERVICE_NAME" 2>/dev/null
log_message "Service stopped and disabled"

# Remove service file
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
    log_message "Removing service file..."
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    log_message "Service file removed"
fi

# Remove firewall rules
log_message "Removing firewall rules..."

# Remove from iptables
if command -v iptables >/dev/null 2>&1; then
    log_message "Removing iptables rule..."
    iptables -D INPUT -p tcp --dport 2000 -j ACCEPT 2>/dev/null
    
    # Save iptables rules
    if [ -f /etc/redhat-release ]; then
        service iptables save 2>/dev/null
    elif [ -f /etc/debian_version ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi
fi

# Remove from firewalld
if command -v firewall-cmd >/dev/null 2>&1; then
    log_message "Removing firewalld rule..."
    firewall-cmd --permanent --remove-port=2000/tcp 2>/dev/null
    firewall-cmd --reload 2>/dev/null
fi

# Remove from UFW
if command -v ufw >/dev/null 2>&1; then
    log_message "Removing UFW rule..."
    ufw delete allow 2000/tcp 2>/dev/null
    ufw reload 2>/dev/null
fi

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    log_message "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
    log_message "Installation directory removed"
fi

# Remove log file
if [ -f "$LOG_FILE" ]; then
    log_message "Removing log file..."
    rm -f "$LOG_FILE"
    log_message "Log file removed"
fi

# Final cleanup
log_message "Performing final cleanup..."

# Remove any leftover temporary files
rm -rf /tmp/zipline_* 2>/dev/null

# Reload systemd one final time
systemctl daemon-reload

log_message "Uninstallation completed successfully"
echo "Zipline has been completely uninstalled from the system."
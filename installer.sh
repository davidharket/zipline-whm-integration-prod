#!/bin/bash

# Function to handle errors
handle_error() {
    echo "Error: $1"
    exit 1
}

# Function to configure firewall
configure_firewall() {
    echo "Configuring firewall for Zipline on port 2000..."

    # Check for iptables
    if command -v iptables >/dev/null 2>&1; then
        echo "Found iptables, configuring..."

        # Remove existing rule if it exists
        iptables -D INPUT -p tcp --dport 2000 -j ACCEPT 2>/dev/null

        # Find the position of the REJECT or DROP rule if it exists
        REJECT_LINE=$(iptables -L INPUT --line-numbers | grep -E 'REJECT|DROP' | head -n1 | awk '{print $1}')

        if [ -n "$REJECT_LINE" ]; then
            # Insert before the REJECT/DROP rule
            iptables -I INPUT "$REJECT_LINE" -p tcp --dport 2000 -j ACCEPT
        else
            # If no REJECT/DROP rule, append to the end
            iptables -A INPUT -p tcp --dport 2000 -j ACCEPT
        fi

        # Save iptables rules
        if [ -f /etc/redhat-release ]; then
            service iptables save
        elif [ -f /etc/debian_version ]; then
            iptables-save > /etc/iptables/rules.v4
        fi
    fi

    # Check for firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        echo "Found firewalld, configuring..."
        firewall-cmd --permanent --add-port=2000/tcp
        firewall-cmd --reload
    fi

    # Check for UFW
    if command -v ufw >/dev/null 2>&1; then
        echo "Found UFW, configuring..."
        ufw allow 2000/tcp
        ufw reload
    fi

    echo "Firewall configuration completed."
}

# Directory setup
INSTALL_DIR="/usr/local/zipline"
SERVICE_NAME="zipline"

# Create necessary directories
mkdir -p $INSTALL_DIR || handle_error "Failed to create installation directory"

# Create the main router script
cat > $INSTALL_DIR/zipline-router.php << 'EOL'
<?php
if ($_SERVER['REQUEST_URI'] === '/backup') {
    require __DIR__ . '/zipline-backup.php';
    exit;
} else {
    require __DIR__ . '/zipline-server.php';
    exit;
}
EOL

# Create the backup receiver endpoint
cat > $INSTALL_DIR/zipline-backup.php << 'EOL'
<?php
/**
 * zipline-backup.php
 *
 * This endpoint is part of the Zipline migration process. It receives a backup ZIP archive
 * (via a POST request with multipart/form-data) along with a target domain and an optional
 * admin email. It will:
 *   - Determine the cPanel account owner for the domain (via /etc/trueuserdomains)
 *   - Determine the document root (/home/{owner}/public_html)
 *   - Extract the backup archive into a temporary folder
 *   - Replace the current wp-content directory with the backup version
 *   - Update wp-config.php and .htaccess if provided in the backup
 *   - Import the database dump file (matching database_backup_*.sql)
 *   - Optionally process metadata.json (if present)
 *   - Set proper file/directory permissions and ownership for the migrated files
 *   - Clean up temporary files and respond with a JSON result.
 */

// Enable error logging
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/zipline-backup.log');

/**
 * Log messages to the error log.
 *
 * @param string $message
 * @param mixed  $data Optional additional data to log.
 */
function ziplog($message, $data = null) {
    $logMessage = "[" . date('Y-m-d H:i:s') . "] " . $message;
    if ($data !== null) {
        if (is_array($data) || is_object($data)) {
            $logMessage .= "\n" . print_r($data, true);
        } else {
            $logMessage .= " " . $data;
        }
    }
    error_log($logMessage);
}

/**
 * Send a JSON response and exit.
 *
 * @param string $status  'success' or 'error'
 * @param string $message Response message.
 * @param array  $data    Additional data to include.
 */
function respond($status, $message, $data = []) {
    ziplog("Response: Status=$status, Message=$message", $data);
    header('Content-Type: application/json');
    echo json_encode(['status' => $status, 'message' => $message, 'data' => $data]);
    exit;
}

/**
 * Recursively copy files and directories from source to destination.
 *
 * @param string $src Source directory.
 * @param string $dst Destination directory.
 */
function recursiveCopy($src, $dst) {
    ziplog("Starting recursive copy", ['from' => $src, 'to' => $dst]);

    if (!file_exists($src)) {
        ziplog("Source does not exist: " . $src);
        return;
    }

    if (!file_exists($dst)) {
        mkdir($dst, 0755, true);
    }

    $files = scandir($src);
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }
        $srcFile = $src . '/' . $file;
        $dstFile = $dst . '/' . $file;

        if (is_dir($srcFile)) {
            recursiveCopy($srcFile, $dstFile);
        } else {
            if (!copy($srcFile, $dstFile)) {
                ziplog("Failed to copy file", ['file' => $file, 'error' => error_get_last()]);
            }
        }
    }
    ziplog("Completed recursive copy", ['from' => $src, 'to' => $dst]);
}

/**
 * Recursively set ownership and permissions for a given path.
 *
 * @param string $path  File or directory path.
 * @param string $owner Owner username.
 */
function setOwnershipAndPermissions($path, $owner) {
    ziplog("Setting ownership/permissions", ['path' => $path, 'owner' => $owner]);

    if (is_dir($path)) {
        chmod($path, 0755);
        chown($path, $owner);
        chgrp($path, $owner);
        $items = scandir($path);
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') {
                continue;
            }
            setOwnershipAndPermissions($path . '/' . $item, $owner);
        }
    } else {
        chmod($path, 0644);
        chown($path, $owner);
        chgrp($path, $owner);
    }
}

/**
 * Recursively remove a directory.
 *
 * @param string $dir Directory to remove.
 */
function rrmdir($dir) {
    if (is_dir($dir)) {
        $objects = scandir($dir);
        foreach ($objects as $object) {
            if ($object != "." && $object != "..") {
                $path = $dir . "/" . $object;
                if (is_dir($path)) {
                    rrmdir($path);
                } else {
                    unlink($path);
                }
            }
        }
        rmdir($dir);
    }
}

/**
 * Import a database dump found in the backup.
 *
 * Searches for a file matching database_backup_*.sql in the temporary extraction directory.
 *
 * @param string $tempDir The temporary directory where the backup was extracted.
 * @param string $docRoot The document root of the target site.
 */
function importDatabaseDump($tempDir, $docRoot) {
    ziplog("Starting database import check");
    $dbDumpFiles = glob($tempDir . '/database_backup_*.sql');
    if (!$dbDumpFiles || count($dbDumpFiles) === 0) {
        ziplog("No database dump found matching pattern database_backup_*.sql");
        return;
    }
    // If multiple dump files exist, pick the first one found.
    $dbDumpFile = $dbDumpFiles[0];
    ziplog("Found database dump file: " . $dbDumpFile);

    $wpConfigPath = $docRoot . '/wp-config.php';
    if (!file_exists($wpConfigPath)) {
        ziplog("wp-config.php not found at: " . $wpConfigPath);
        respond('error', 'Cannot import database: wp-config.php not found.');
    }

    ziplog("Reading wp-config.php for database credentials");
    $configContents = file_get_contents($wpConfigPath);
    $dbName = $dbUser = $dbPass = $dbHost = null;
    if (preg_match("/define\(\s*'DB_NAME'\s*,\s*'([^']+)'/", $configContents, $matches)) {
        $dbName = $matches[1];
        ziplog("Found DB_NAME: " . $dbName);
    }
    if (preg_match("/define\(\s*'DB_USER'\s*,\s*'([^']+)'/", $configContents, $matches)) {
        $dbUser = $matches[1];
        ziplog("Found DB_USER: " . $dbUser);
    }
    if (preg_match("/define\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'/", $configContents, $matches)) {
        $dbPass = $matches[1];
        ziplog("Found DB_PASSWORD: [hidden]");
    }
    if (preg_match("/define\(\s*'DB_HOST'\s*,\s*'([^']+)'/", $configContents, $matches)) {
        $dbHost = $matches[1];
        ziplog("Found DB_HOST: " . $dbHost);
    }

    if (!$dbName || !$dbUser || $dbPass === null || !$dbHost) {
        ziplog("Failed to parse database credentials", [
            'name_found' => !empty($dbName),
            'user_found' => !empty($dbUser),
            'pass_found' => ($dbPass !== null),
            'host_found' => !empty($dbHost)
        ]);
        respond('error', 'Failed to parse database credentials from wp-config.php.');
    }

    ziplog("Preparing to import database dump");
    $cmd = "mysql -h " . escapeshellarg($dbHost) . " -u " . escapeshellarg($dbUser) .
           " -p" . escapeshellarg($dbPass) . " " . escapeshellarg($dbName) .
           " < " . escapeshellarg($dbDumpFile);
    ziplog("Executing mysql import command: " . $cmd);
    $output = shell_exec($cmd . " 2>&1");
    ziplog("Database import completed with output", ['output' => $output]);
    file_put_contents("/var/log/wp_db_import.log", "Database import output: " . $output . "\n", FILE_APPEND);
}

// ---------------------------------------------------------------------
// Main Processing Logic
// ---------------------------------------------------------------------

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    ziplog("Invalid request method: " . $_SERVER['REQUEST_METHOD']);
    respond('error', 'Invalid request method.');
}

// Log the request details
ziplog("Received backup request", [
    'REQUEST_METHOD' => $_SERVER['REQUEST_METHOD'],
    'FILES' => $_FILES,
    'POST' => $_POST
]);

// Validate required inputs: backup file and domain
if (!isset($_FILES['backup']) || !isset($_POST['domain'])) {
    ziplog("Missing required fields", [
        'files_set'  => isset($_FILES['backup']),
        'domain_set' => isset($_POST['domain'])
    ]);
    respond('error', 'Missing required fields: backup file and domain.');
}

$domain = trim($_POST['domain']);
$backupFile = $_FILES['backup'];
$adminEmail = isset($_POST['adminEmail']) ? trim($_POST['adminEmail']) : '';

ziplog("Processing request", [
    'domain'       => $domain,
    'backup_file'  => $backupFile['name'],
    'admin_email'  => $adminEmail
]);

if ($backupFile['error'] !== UPLOAD_ERR_OK) {
    ziplog("File upload error", [
        'error_code' => $backupFile['error'],
        'file_info'  => $backupFile
    ]);
    respond('error', 'File upload error: ' . $backupFile['error']);
}

// Save the uploaded ZIP archive to a temporary file
$tempFile = sys_get_temp_dir() . '/' . basename($backupFile['name']);
ziplog("Moving uploaded file", [
    'from' => $backupFile['tmp_name'],
    'to'   => $tempFile
]);

if (!move_uploaded_file($backupFile['tmp_name'], $tempFile)) {
    ziplog("Failed to move uploaded file", ['error' => error_get_last()]);
    respond('error', 'Failed to move uploaded file.');
}

// Lookup domain owner using /etc/trueuserdomains
$trueUserDomainsFile = '/etc/trueuserdomains';
ziplog("Looking up domain owner in: " . $trueUserDomainsFile);

if (!file_exists($trueUserDomainsFile)) {
    ziplog("Domain mapping file not found");
    respond('error', 'Unable to locate user domain mapping file.');
}

$owner = null;
$lines = file($trueUserDomainsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
ziplog("Found " . count($lines) . " domain mappings");

foreach ($lines as $line) {
    $parts = explode(':', $line);
    if (count($parts) >= 2) {
        $mappedDomain = trim($parts[0]);
        $username     = trim($parts[1]);
        ziplog("Checking domain mapping", [
            'mapped_domain' => $mappedDomain,
            'username'      => $username,
            'target_domain' => $domain
        ]);
        if (strcasecmp($mappedDomain, $domain) === 0) {
            $owner = $username;
            ziplog("Found matching owner: " . $owner);
            break;
        }
    }
}

if (!$owner) {
    ziplog("No owner found for domain: " . $domain);
    respond('error', 'No matching user found for domain.');
}

// Set the document root based on the owner
$docRoot = "/home/{$owner}/public_html";
ziplog("Document root set to: " . $docRoot);

// Create a temporary directory for extraction
$tempDir = sys_get_temp_dir() . '/backup_' . time();
ziplog("Creating temporary directory: " . $tempDir);
if (!mkdir($tempDir, 0755, true)) {
    ziplog("Failed to create temp directory", ['error' => error_get_last()]);
    respond('error', 'Failed to create temporary extraction directory.');
}

// Extract the ZIP archive
ziplog("Opening ZIP archive: " . $tempFile);
$zip = new ZipArchive();
$zipResult = $zip->open($tempFile);
if ($zipResult === TRUE) {
    ziplog("ZIP file opened successfully, contains " . $zip->numFiles . " files");
    for ($i = 0; $i < $zip->numFiles; $i++) {
        ziplog("ZIP contains: " . $zip->getNameIndex($i));
    }
    ziplog("Extracting to: " . $tempDir);
    if (!$zip->extractTo($tempDir)) {
        ziplog("Failed to extract ZIP", ['error' => error_get_last()]);
        respond('error', 'Failed to extract ZIP archive.');
    }
    $zip->close();
    unlink($tempFile);
    $extractedFiles = scandir($tempDir);
    ziplog("Extracted contents", $extractedFiles);
} else {
    ziplog("Failed to open ZIP file", ['error_code' => $zipResult]);
    unlink($tempFile);
    respond('error', 'Failed to open ZIP archive.');
}

// ---------------------------------------------------------------------
// Process Extracted Backup Files
// ---------------------------------------------------------------------

// 1. Update wp-config.php if present in the backup
$extractedWpConfig = $tempDir . '/wp-config.php';
if (file_exists($extractedWpConfig)) {
    ziplog("Updating wp-config.php");
    if (!copy($extractedWpConfig, $docRoot . '/wp-config.php')) {
        ziplog("Failed to update wp-config.php", ['error' => error_get_last()]);
        respond('error', 'Failed to update wp-config.php.');
    }
} else {
    ziplog("wp-config.php not found in backup, skipping update.");
}

// 2. Update .htaccess if present in the backup
$extractedHtaccess = $tempDir . '/.htaccess';
if (file_exists($extractedHtaccess)) {
    ziplog("Updating .htaccess");
    if (!copy($extractedHtaccess, $docRoot . '/.htaccess')) {
        ziplog("Failed to update .htaccess", ['error' => error_get_last()]);
        respond('error', 'Failed to update .htaccess.');
    }
} else {
    ziplog(".htaccess not found in backup, skipping update.");
}

// 3. Process metadata.json if it exists (optional)
$metadataFile = $tempDir . '/metadata.json';
if (file_exists($metadataFile)) {
    $metadataContents = file_get_contents($metadataFile);
    $metadata = json_decode($metadataContents, true);
    if (json_last_error() === JSON_ERROR_NONE) {
        ziplog("Parsed metadata.json", $metadata);
    } else {
        ziplog("Failed to parse metadata.json", ['error' => json_last_error_msg()]);
    }
} else {
    ziplog("metadata.json not found in backup.");
}

// 4. Replace wp-content entirely if present in the backup
$extractedWpContent = $tempDir . '/wp-content';
$destinationWpContent = $docRoot . '/wp-content';
if (is_dir($extractedWpContent)) {
    ziplog("Replacing wp-content directory");
    // Remove the existing wp-content folder if it exists
    if (is_dir($destinationWpContent)) {
        rrmdir($destinationWpContent);
        ziplog("Existing wp-content removed");
    }
    // Copy the backup wp-content to the destination
    recursiveCopy($extractedWpContent, $destinationWpContent);
    ziplog("wp-content directory replaced successfully");
} else {
    ziplog("wp-content directory not found in backup, skipping replacement.");
}

// 5. Import the database dump (database_backup_*.sql)
importDatabaseDump($tempDir, $docRoot);

// 6. Set final file and directory permissions
ziplog("Setting final permissions for document root");
setOwnershipAndPermissions($docRoot, $owner);

// 7. Clean up temporary extraction directory
ziplog("Cleaning up temporary directory");
rrmdir($tempDir);

// Final success response
ziplog("Backup process completed successfully");
respond('success', 'Backup installed successfully.', ['destination' => $docRoot]);
?>

EOL

# Create the main endpoint
cat > $INSTALL_DIR/zipline-server.php << 'EOL'
<?php
/**
 * zipline-server.php
 * Main Zipline server endpoint for handling general requests
 */
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Origin: *');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'error' => 'Method not allowed',
        'received_method' => $_SERVER['REQUEST_METHOD'],
        'expected_method' => 'POST'
    ]);
    exit();
}

$post_data = file_get_contents('php://input');
$json_data = json_decode($post_data, true);

if ($json_data === null) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Invalid JSON data',
        'received_data' => $post_data
    ]);
    exit();
}

$response = [
    'status' => 'success',
    'message' => 'Request processed successfully',
    'received_data' => $json_data
];

echo json_encode($response);
EOL

# Create systemd service file
cat > /etc/systemd/system/$SERVICE_NAME.service << EOL
[Unit]
Description=Zipline WHM Plugin Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/cpanel/ea-php81/root/usr/bin/php -S 0.0.0.0:2000 $INSTALL_DIR/zipline-router.php
WorkingDirectory=$INSTALL_DIR
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOL

# Set proper permissions
chmod 755 $INSTALL_DIR/*.php || handle_error "Failed to set permissions"
chown -R root:root $INSTALL_DIR || handle_error "Failed to set ownership"

# Configure firewall
configure_firewall

# Reload systemd, enable and start the service
systemctl daemon-reload || handle_error "Failed to reload systemd"
systemctl enable $SERVICE_NAME || handle_error "Failed to enable service"
systemctl restart $SERVICE_NAME || handle_error "Failed to start service"

echo "Zipline installation completed successfully!"
echo "Server IP Addresses:"
# Get IPv4 addresses
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | while read -r ip; do
    echo "  http://$ip:2000        (General endpoint)"
    echo "  http://$ip:2000/backup (Backup endpoint)"
done
echo "To check the status, run: systemctl status $SERVICE_NAME"

# Verify the service is running
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "Zipline service is running successfully"
else
    handle_error "Zipline service failed to start"
fi

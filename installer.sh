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
mkdir -p "$INSTALL_DIR" || handle_error "Failed to create installation directory"

# Create the main router script
cat > "$INSTALL_DIR/zipline-router.php" << 'EOL'
<?php
if ($_SERVER['REQUEST_URI'] === '/backup') {
    require __DIR__ . '/zipline-backup.php';
    exit;
} else {
    require __DIR__ . '/zipline-server.php';
    exit;
}
?>
EOL

# Create the backup receiver endpoint (zipline-backup.php)
cat > "$INSTALL_DIR/zipline-backup.php" << 'EOL'
<?php
/**
 * zipline-backup.php
 *
 * This endpoint handles WordPress backup restoration with cPanel integration.
 * It now uses a command-line WHM API approach to update MySQL credentials.
 *
 * The new approach extracts the original database credentials from wp-config.php,
 * removes any existing prefix, and then applies the cPanel account's prefix.
 * If the resulting database or user already exists, new randomized names (and user password)
 * are generated.
 */

// Error configuration
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/zipline-backup.log');

/**
 * Log a message.
 */
function ziplog($message, $data = null) {
    $logMessage = "[" . date('Y-m-d H:i:s') . "] " . $message;
    if ($data !== null) {
        $logMessage .= "\n" . print_r($data, true);
    }
    error_log($logMessage);
}

/**
 * Return a JSON response and exit.
 */
function respond($status, $message, $data = []) {
    ziplog("Response: $status - $message", $data);
    header('Content-Type: application/json');
    exit(json_encode(['status' => $status, 'message' => $message, 'data' => $data]));
}

/**
 * Executes a WHM API 1 call using the whmapi1 command.
 *
 * @param string $function The WHM API function.
 * @param array  $params   Associative array of parameters.
 * @return array|null Decoded JSON response or null on error.
 */
function make_whm_api_call($function, $params) {
    // Note: $cpanel_username and $module would be defined in context if needed.
    // For this sample, we assume that WHM API calls (if used) are not needed.
    $command = "sudo /usr/local/cpanel/bin/whmapi --output=json " . escapeshellarg($function);
    foreach ($params as $key => $value) {
        $command .= " " . escapeshellarg($key) . "=" . escapeshellarg($value);
    }
    ziplog("Executing WHM API call: $command");
    exec($command . " 2>&1", $output, $return_var);
    $result = implode("\n", $output);
    ziplog("WHM API call return code: $return_var");
    ziplog("WHM API result: " . $result);

    if ($return_var !== 0) {
        ziplog("WHM API call failed with return code: $return_var", true);
        return null;
    }
    $decoded_result = json_decode($result, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        ziplog("JSON decode error: " . json_last_error_msg(), true);
        ziplog("Full WHM API output: " . $result, true);
        return null;
    }
    return $decoded_result;
}

/**
 * Executes a cPanel UAPI call using the uapi command for a specific account.
 *
 * @param string $cpanel_username The cPanel username.
 * @param string $module          The UAPI module (e.g., 'Mysql').
 * @param string $function        The UAPI function (e.g., 'create_database').
 * @param array  $params          Associative array of parameters.
 *
 * @return array|null Decoded JSON response or null on error.
 */
function make_uapi_call($cpanel_username, $module, $function, $params) {
    $command = "sudo /usr/local/cpanel/bin/uapi --user=" . escapeshellarg($cpanel_username)
        . " " . escapeshellarg($module) . " " . escapeshellarg($function);
    foreach ($params as $key => $value) {
        $command .= " " . escapeshellarg($key) . "=" . escapeshellarg($value);
    }
    $command .= " --output=json";

    ziplog("Executing UAPI call: $command");
    exec($command . " 2>&1", $output, $return_var);
    $result = implode("\n", $output);
    ziplog("UAPI call return code: $return_var");
    ziplog("UAPI result: " . $result);

    if ($return_var !== 0) {
        ziplog("UAPI call failed with return code: $return_var", true);
        return null;
    }
    $decoded_result = json_decode($result, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        ziplog("JSON decode error: " . json_last_error_msg(), true);
        ziplog("Full UAPI output: " . $result, true);
        return null;
    }
    return $decoded_result;
}

/**
 * Check if a database already exists.
 */
function check_database_exists($cpanel_username, $dbName) {
    $result = make_uapi_call($cpanel_username, 'Mysql', 'list_databases', []);
    if ($result && isset($result['result']['data']) && is_array($result['result']['data'])) {
        foreach ($result['result']['data'] as $db) {
            // Depending on the API version, the key holding the db name may vary.
            if (isset($db['name']) && $db['name'] === $dbName) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Check if a MySQL user already exists.
 */
function check_user_exists($cpanel_username, $dbUser) {
    $result = make_uapi_call($cpanel_username, 'Mysql', 'list_users', []);
    if ($result && isset($result['result']['data']) && is_array($result['result']['data'])) {
        foreach ($result['result']['data'] as $user) {
            // Depending on the API output, adjust the key name accordingly.
            if (isset($user['user']) && $user['user'] === $dbUser) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Generate a random string of specified length.
 */
function generateRandomString($length = 8) {
    // Using random_bytes if available.
    return substr(bin2hex(random_bytes((int)ceil($length/2))), 0, $length);
}

/**
 * Generate a strong random string of specified length.
 * Uses upper-case, lower-case, digits, and symbols.
 *
 * @param int $length The desired length.
 * @return string The generated password.
 */
function generateStrongRandomString($length = 16) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    $charLen = strlen($chars);
    $result = '';
    for ($i = 0; $i < $length; $i++) {
        $index = random_int(0, $charLen - 1);
        $result .= $chars[$index];
    }
    return $result;
}

/**
 * Update MySQL credentials by creating a new database and user,
 * then granting privileges to the new user.
 *
 * If the computed (prefixed) names already exist—or if creation fails because of a collision
 * or weak password—the function generates new random credentials and retries.
 *
 * @param string $cpanel_username The cPanel username.
 * @param string $old_db_name     The original database name (for reference).
 * @param string $base_db_name    The original (unprefixed) database name from wp-config.
 * @param string $old_db_user     The original database user (for reference).
 * @param string $base_db_user    The original (unprefixed) user name from wp-config.
 * @param string $old_password    The original database password.
 * @return array Returns an associative array with keys 'success', 'message', and the new credentials.
 */
function update_mysql_credentials($cpanel_username, $old_db_name, $base_db_name, $old_db_user, $base_db_user, $old_password) {
    ziplog("Updating MySQL credentials for user: $cpanel_username");

    $maxRetries = 3;
    $attempt = 0;
    $success = false;

    // Start with the default new names; use the old password by default.
    $new_db_name = $cpanel_username . '_' . $base_db_name;
    $new_db_user = $cpanel_username . '_' . $base_db_user;
    $new_password = $old_password;

    while ($attempt < $maxRetries && !$success) {
        ziplog("Attempt " . ($attempt + 1) . ": Trying new DB Name: $new_db_name, new DB User: $new_db_user");

        // Try to create the database using UAPI
        $create_db_result = make_uapi_call($cpanel_username, 'Mysql', 'create_database', [
            'name' => $new_db_name
        ]);
        if ($create_db_result !== null && isset($create_db_result['result']['status']) && $create_db_result['result']['status'] == 1) {
            ziplog("Database created successfully");
        } else {
            // Check if error indicates database already exists
            $errors = isset($create_db_result['result']['errors']) ? $create_db_result['result']['errors'] : [];
            if (is_array($errors) && count($errors) > 0 && strpos($errors[0], 'already exists') !== false) {
                ziplog("Database '$new_db_name' already exists. Generating new random credentials.");
                // Generate new random suffix and password.
                $randomSuffix = generateRandomString(6);
                $new_db_name = $cpanel_username . '_' . $base_db_name . '_' . $randomSuffix;
                $new_db_user = $cpanel_username . '_' . $base_db_user . '_' . $randomSuffix;
                $new_password = generateStrongRandomString(16);
                $attempt++;
                continue;
            } else {
                ziplog("Failed to create database: " . json_encode($create_db_result), true);
                return ['success' => false, 'message' => 'Failed to create database'];
            }
        }

        // Create database user using UAPI
        $create_user_result = make_uapi_call($cpanel_username, 'Mysql', 'create_user', [
            'name'     => $new_db_user,
            'password' => $new_password
        ]);
        if ($create_user_result === null || !isset($create_user_result['result']['status']) || $create_user_result['result']['status'] != 1) {
            $errors = isset($create_user_result['result']['errors']) ? $create_user_result['result']['errors'] : [];
            if (is_array($errors) && count($errors) > 0) {
                if (strpos($errors[0], 'already exists') !== false) {
                    ziplog("User '$new_db_user' already exists. Generating new random credentials.");
                } elseif (strpos($errors[0], 'too weak') !== false) {
                    ziplog("The given password is too weak. Generating new strong random credentials.");
                } else {
                    ziplog("Failed to create database user: " . json_encode($create_user_result), true);
                    return ['success' => false, 'message' => 'Failed to create database user'];
                }
                // Generate new random suffix and a strong password.
                $randomSuffix = generateRandomString(6);
                $new_db_name = $cpanel_username . '_' . $base_db_name . '_' . $randomSuffix;
                $new_db_user = $cpanel_username . '_' . $base_db_user . '_' . $randomSuffix;
                $new_password = generateStrongRandomString(16);
                $attempt++;
                continue;
            }
        }
        ziplog("Database user created successfully");

        // Grant privileges using UAPI
        $set_privileges_result = make_uapi_call($cpanel_username, 'Mysql', 'set_privileges_on_database', [
            'user'       => $new_db_user,
            'database'   => $new_db_name,
            'privileges' => 'ALL PRIVILEGES'
        ]);
        if ($set_privileges_result === null || !isset($set_privileges_result['result']['status']) || $set_privileges_result['result']['status'] != 1) {
            ziplog("Failed to set privileges on database: " . json_encode($set_privileges_result), true);
            return ['success' => false, 'message' => 'Failed to set privileges on database'];
        }
        ziplog("Privileges set on database successfully");

        // If we reach this point, everything succeeded.
        $success = true;
    }

    if (!$success) {
        return ['success' => false, 'message' => 'Exceeded maximum retries for database/user creation'];
    }

    return [
        'success'    => true,
        'message'    => 'MySQL credentials updated successfully',
        'dbName'     => $new_db_name,
        'dbUser'     => $new_db_user,
        'dbPassword' => $new_password
    ];
}

/**
 * Get proper prefixed database names for cPanel.
 *
 * This function removes any existing prefix from the original names
 * and returns an array with the unprefixed base names.
 */
function getBaseDbNames($owner, $dbName, $dbUser) {
    // Remove any prefix matching "owner_" from the original names
    $pattern = '/^' . preg_quote($owner . '_', '/') . '/';
    $baseDbName = preg_replace($pattern, '', $dbName);
    $baseDbUser = preg_replace($pattern, '', $dbUser);
    return [
        'baseDbName' => $baseDbName,
        'baseDbUser' => $baseDbUser
    ];
}

/**
 * Recursively copy files from source to destination.
 */
function recursiveCopy($src, $dst) {
    if (!file_exists($src)) return;
    $dir = opendir($src);
    @mkdir($dst, 0755);
    while (($file = readdir($dir)) !== false) {
        if ($file == '.' || $file == '..') continue;
        $srcFile = "$src/$file";
        $dstFile = "$dst/$file";
        is_dir($srcFile) ? recursiveCopy($srcFile, $dstFile) : copy($srcFile, $dstFile);
    }
    closedir($dir);
}

/**
 * Extract database credentials from wp-config.php.
 */
function extractDbCredentials($wpConfigPath) {
    $content = file_get_contents($wpConfigPath);
    if ($content === false) {
        throw new Exception("Failed to read wp-config.php");
    }
    $required = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'];
    $creds = [];
    foreach ($required as $key) {
        if (!preg_match("/define\(\s*'$key'\s*,\s*'([^']+)'/", $content, $match)) {
            throw new Exception("Could not find $key in wp-config.php");
        }
        $creds[$key] = $match[1];
    }
    return $creds;
}

/**
 * Update wp-config.php with new database credentials.
 */
function updateWpConfig($wpConfigPath, $newCreds) {
    $content = file_get_contents($wpConfigPath);
    if ($content === false) {
        throw new Exception("Failed to read wp-config.php for updating");
    }
    foreach ($newCreds as $key => $value) {
        $content = preg_replace(
            "/define\(\s*'$key'\s*,\s*'[^']*'\s*\);/",
            "define('$key', '$value');",
            $content
        );
    }
    if (file_put_contents($wpConfigPath, $content) === false) {
        throw new Exception("Failed to update wp-config.php");
    }
}

/**
 * Utility function: recursively remove a directory.
 */
function rrmdir($dir) {
    if (!is_dir($dir)) return;
    foreach (scandir($dir) as $file) {
        if ($file == '.' || $file == '..') continue;
        $path = "$dir/$file";
        is_dir($path) ? rrmdir($path) : unlink($path);
    }
    rmdir($dir);
}

// Main Processing
try {
    // Validate request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        respond('error', 'Invalid request method');
    }

    // Validate inputs
    if (!isset($_FILES['backup']) || !isset($_POST['domain'])) {
        respond('error', 'Missing required fields');
    }

    // Process domain ownership
    $domain = trim($_POST['domain']);
    $owner = null;
    foreach (file('/etc/trueuserdomains', FILE_IGNORE_NEW_LINES) as $line) {
        list($mappedDomain, $user) = explode(':', $line);
        if (strcasecmp(trim($mappedDomain), $domain) === 0) {
            $owner = trim($user);
            break;
        }
    }
    if (!$owner) {
        respond('error', 'Domain owner not found');
    }

    // Setup paths
    $docRoot = "/home/$owner/public_html";
    if (!is_dir($docRoot)) {
        respond('error', 'Document root not found');
    }

    // Create and validate temp directory
    $tempDir = sys_get_temp_dir() . '/zipline_' . bin2hex(random_bytes(8));
    if (!mkdir($tempDir, 0755, true)) {
        respond('error', 'Failed to create temp directory');
    }

    // Extract backup archive
    $zip = new ZipArchive;
    if ($zip->open($_FILES['backup']['tmp_name']) !== TRUE) {
        rrmdir($tempDir);
        respond('error', 'Failed to open ZIP archive');
    }
    $zip->extractTo($tempDir);
    $zip->close();

    // Locate SQL dump file (if any)
    // Now looking specifically for files like: database_backup_2025-02-02_18-48-17.sql
    $sqlFiles = glob("$tempDir/database_backup_*.sql");
    $sqlDumpPath = !empty($sqlFiles) ? $sqlFiles[0] : null;

    // Handle wp-config.php
    $wpConfig = "$docRoot/wp-config.php";
    if (file_exists("$tempDir/wp-config.php")) {
        // Backup existing wp-config if it exists
        if (file_exists($wpConfig)) {
            copy($wpConfig, $wpConfig . '.bak');
        }
        copy("$tempDir/wp-config.php", $wpConfig);
    }
    if (!file_exists($wpConfig)) {
        rrmdir($tempDir);
        respond('error', 'wp-config.php not found');
    }

    // Extract and validate database credentials from wp-config.php
    try {
        $origCreds = extractDbCredentials($wpConfig);
    } catch (Exception $e) {
        rrmdir($tempDir);
        respond('error', 'Failed to extract database credentials: ' . $e->getMessage());
    }

    // Get base (unprefixed) names from the original credentials.
    $baseNames = getBaseDbNames($owner, $origCreds['DB_NAME'], $origCreds['DB_USER']);

    // Update MySQL credentials using the new approach.
    $updateResult = update_mysql_credentials(
        $owner,
        $origCreds['DB_NAME'],
        $baseNames['baseDbName'],
        $origCreds['DB_USER'],
        $baseNames['baseDbUser'],
        $origCreds['DB_PASSWORD']
    );
    if (!$updateResult['success']) {
        rrmdir($tempDir);
        respond('error', 'Database update failed: ' . $updateResult['message']);
    }
    ziplog("Database update successful: " . $updateResult['message']);

    // If an SQL dump is provided, attempt to import it using the mysql command-line.
    if (!empty($sqlDumpPath) && file_exists($sqlDumpPath)) {
        ziplog("Importing SQL dump using mysql command-line", ['sql_file' => $sqlDumpPath]);

        // First set SQL mode to handle timestamp issues
        $setModeCmd = sprintf(
            "mysql -u%s -p%s -e '%s'",
            escapeshellarg($updateResult['dbUser']),
            escapeshellarg($updateResult['dbPassword']),
            "SET GLOBAL sql_mode='NO_ENGINE_SUBSTITUTION,ALLOW_INVALID_DATES';"
        );
        exec($setModeCmd);

        // Build the mysql command with modified SQL mode
        $mysqlUser = escapeshellarg($updateResult['dbUser']);
        $mysqlPassword = escapeshellarg($updateResult['dbPassword']);
        $mysqlDb = escapeshellarg($updateResult['dbName']);
        $sqlFile = escapeshellarg($sqlDumpPath);

        // Import with modified SQL mode
        $cmd = "mysql -u $mysqlUser -p$mysqlPassword $mysqlDb -e 'SET SESSION sql_mode=\"NO_ENGINE_SUBSTITUTION,ALLOW_INVALID_DATES\"; SOURCE $sqlFile;'";

        // Log command (with password redacted)
        ziplog("Executing SQL import command: " . preg_replace('/-p[^ ]+/', '-p[REDACTED]', $cmd));

        exec($cmd, $output, $return_var);
        ziplog("SQL import return code: $return_var", $output);

        if ($return_var !== 0) {
            ziplog("SQL Import failed", ['return_code' => $return_var, 'output' => $output]);
            // Note: We continue even if import fails, as we want the rest of the restoration to proceed
        } else {
            ziplog("SQL dump imported successfully", ['database' => $updateResult['dbName']]);
        }
    }
    // Update wp-config.php with new credentials
    $newCreds = [
        'DB_NAME'     => $updateResult['dbName'],
        'DB_USER'     => $updateResult['dbUser'],
        'DB_PASSWORD' => $updateResult['dbPassword'],
        'DB_HOST'     => $origCreds['DB_HOST']
    ];
    updateWpConfig($wpConfig, $newCreds);
    ziplog("wp-config.php updated with new credentials", [
        'database' => $updateResult['dbName'],
        'user'     => $updateResult['dbUser']
    ]);

    // Deploy wp-content directory: OVERWRITE current wp-content
    if (is_dir("$tempDir/wp-content")) {
        if (is_dir("$docRoot/wp-content")) {
            // Remove the current wp-content directory entirely.
            rrmdir("$docRoot/wp-content");
        }
        recursiveCopy("$tempDir/wp-content", "$docRoot/wp-content");
        // Set proper permissions
        $chmodCmd = "chmod -R 755 " . escapeshellarg("$docRoot/wp-content");
        $chownCmd = "chown -R " . escapeshellarg("$owner:$owner") . " " . escapeshellarg("$docRoot/wp-content");
        exec($chmodCmd);
        exec($chownCmd);
    }

    // Cleanup temporary files
    rrmdir($tempDir);

    // Success response
    respond('success', 'Deployment completed successfully', [
        'path'     => $docRoot,
        'database' => $updateResult['dbName'],
        'backups_created' => [
            'wp_config'  => file_exists($wpConfig . '.bak')
        ]
    ]);

} catch (Exception $e) {
    // Cleanup on error
    if (isset($tempDir) && is_dir($tempDir)) {
        rrmdir($tempDir);
    }
    http_response_code(500);
    respond('error', 'Processing failed: ' . $e->getMessage());
}

EOL

# Create the main endpoint (zipline-server.php)
cat > "$INSTALL_DIR/zipline-server.php" << 'EOL'
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
?>
EOL

# Create systemd service file with PHP configuration flags
cat > /etc/systemd/system/"$SERVICE_NAME".service << EOL
[Unit]
Description=Zipline WHM Plugin Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/cpanel/ea-php81/root/usr/bin/php -d upload_max_filesize=5G -d post_max_size=5G -d max_execution_time=600 -d max_input_time=600 -d memory_limit=512M -S 0.0.0.0:2000 $INSTALL_DIR/zipline-router.php
WorkingDirectory=$INSTALL_DIR
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOL

# Set proper permissions
chmod 755 "$INSTALL_DIR"/*.php || handle_error "Failed to set permissions"
chown -R root:root "$INSTALL_DIR" || handle_error "Failed to set ownership"

# Configure firewall
configure_firewall

# Reload systemd, enable and start the service
systemctl daemon-reload || handle_error "Failed to reload systemd"
systemctl enable "$SERVICE_NAME" || handle_error "Failed to enable service"
systemctl restart "$SERVICE_NAME" || handle_error "Failed to start service"

echo "Zipline installation completed successfully!"
echo "Server IP Addresses:"
# Get IPv4 addresses
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | while read -r ip; do
    echo "  http://$ip:2000        (General endpoint)"
    echo "  http://$ip:2000/backup (Backup endpoint)"
done
echo "To check the status, run: systemctl status $SERVICE_NAME"

# Verify the service is running
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "Zipline service is running successfully"
else
    handle_error "Zipline service failed to start"
fi

# End of installer.sh
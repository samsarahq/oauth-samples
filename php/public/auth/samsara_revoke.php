<?php
require __DIR__ . '/../../vendor/autoload.php';
session_start();

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

// Get refresh token from session
$credentials = $_SESSION['credentials'] ?? null;

if (!$credentials || !isset($credentials['refresh_token'])) {
    die('No refresh token found. Please connect to Samsara first.');
}

$refresh_token = $credentials['refresh_token'];

// Create authorization header
$auth = $_ENV['SAMSARA_CLIENT_ID'] . ':' . $_ENV['SAMSARA_CLIENT_SECRET'];
$encoded_auth = base64_encode($auth);

// Initialize cURL session
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, 'https://api.samsara.com/oauth2/revoke');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Basic ' . $encoded_auth,
    'Content-Type: application/x-www-form-urlencoded'
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'token' => $refresh_token
]));

// Execute request
$response = curl_exec($ch);

// Get HTTP status code
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

// Check for errors
if (curl_errno($ch)) {
    die('Error revoking token: ' . curl_error($ch));
}

// Close cURL session
curl_close($ch);

if ($http_code === 200) {
    // Clear credentials from session
    unset($_SESSION['credentials']);

    // Redirect to home page
    header('Location: /');
    exit();
} else {
    // Display error response
    echo 'Failed to revoke token. API response: ' . $response;
}

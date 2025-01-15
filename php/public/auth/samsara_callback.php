<?php
require __DIR__ . '/../../vendor/autoload.php';
session_start();

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

// Extract code and state from query string
$code = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;


// Log the state parameter for debugging
error_log('OAuth state parameter in callback: ' . $state);

// Log the session oauth_state for debugging
if (isset($_SESSION['oauth_state'])) {
    error_log('OAuth state parameter in session: ' . $_SESSION['oauth_state']);
} else {
    error_log('No oauth_state found in session');
}

// Verify state parameter to prevent CSRF
if (!isset($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
    die('Invalid state parameter');
}

// Create authorization header
$auth = $_ENV['SAMSARA_CLIENT_ID'] . ':' . $_ENV['SAMSARA_CLIENT_SECRET'];
$encoded_auth = base64_encode($auth);

// Initialize cURL session
$ch = curl_init();

// Set cURL options for token exchange
curl_setopt($ch, CURLOPT_URL, 'https://api.samsara.com/oauth2/token');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Basic ' . $encoded_auth,
    'Content-Type: application/x-www-form-urlencoded'
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => 'http://localhost:5000/auth/samsara_callback.php'
]));

// Execute request
$response = curl_exec($ch);

// Check for cURL errors
if (curl_errno($ch)) {
    die('Error exchanging code for tokens: ' . curl_error($ch));
}

// Close cURL session
curl_close($ch);

// Parse response
$token_data = json_decode($response, true);

if (isset($token_data['access_token']) && isset($token_data['refresh_token'])) {
    // Connect to SQLite database
    $db = new SQLite3(__DIR__ . '/../../demo.db');

    // Store tokens in database
    $stmt = $db->prepare('INSERT OR REPLACE INTO demo (access_token, refresh_token) VALUES (:access_token, :refresh_token)');
    $stmt->bindValue(':access_token', $token_data['access_token'], SQLITE3_TEXT);
    $stmt->bindValue(':refresh_token', $token_data['refresh_token'], SQLITE3_TEXT);
    $stmt->execute();

    // Redirect to home page on success
    header('Location: /');
    exit();
} else {
    // Display error response
    echo 'Failed to exchange code for tokens. API response: ';
    echo '<pre>' . print_r($token_data, true) . '</pre>';
}

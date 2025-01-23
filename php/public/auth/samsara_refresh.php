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
curl_setopt($ch, CURLOPT_URL, 'https://api.samsara.com/oauth2/token');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Basic ' . $encoded_auth,
    'Content-Type: application/x-www-form-urlencoded'
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'grant_type' => 'refresh_token',
    'refresh_token' => $refresh_token
]));

// Execute request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    die('Error refreshing token: ' . curl_error($ch));
}

// Close cURL session
curl_close($ch);

// Parse response
$token_data = json_decode($response, true);

if (!isset($token_data['access_token']) || !isset($token_data['refresh_token'])) {
    die('Invalid response from token endpoint');
}

// Calculate expires_at timestamp
$expires_at = time() + $token_data['expires_in'];

// Store new tokens in session
$_SESSION['credentials'] = [
    'access_token' => $token_data['access_token'],
    'refresh_token' => $token_data['refresh_token'],
    'expires_at' => $expires_at
];

// Redirect back to home page
header('Location: /');
exit();

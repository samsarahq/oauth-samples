<?php
require __DIR__ . '/../../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

// Connect to SQLite database
$db = new SQLite3(__DIR__ . '/../../demo.db');

// Get refresh token from database
$result = $db->query('SELECT refresh_token FROM demo');
$row = $result->fetchArray(SQLITE3_ASSOC);

if (!$row || !isset($row['refresh_token'])) {
    die('No refresh token found. Please connect to Samsara first.');
}

$refresh_token = $row['refresh_token'];

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

// Store new tokens in database
$stmt = $db->prepare('UPDATE demo SET access_token = :access_token, refresh_token = :refresh_token');
$stmt->bindValue(':access_token', $token_data['access_token'], SQLITE3_TEXT);
$stmt->bindValue(':refresh_token', $token_data['refresh_token'], SQLITE3_TEXT);
$stmt->execute();

// Redirect back to home page
header('Location: /');
exit();

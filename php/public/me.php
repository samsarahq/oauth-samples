<?php
require __DIR__ . '/../vendor/autoload.php';

error_log('me.php called');

session_start();

// Get credentials from session
$credentials = $_SESSION['credentials'] ?? null;

if (!$credentials || !isset($credentials['access_token'])) {
    die('No access token found. Please connect to Samsara first.');
}

$access_token = $credentials['access_token'];

// Check if token is expired and refresh if necessary
// if (isset($credentials['expires_at']) && $credentials['expires_at'] < time()) {
//     // Token is expired, redirect to refresh endpoint
//     header('Location: /auth/samsara_refresh.php');
//     exit();
// }

$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, 'https://api.samsara.com/me');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $access_token,
    'Accept: application/json'
]);

// Execute request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    die('Error making API request: ' . curl_error($ch));
}

// Get HTTP status code
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

// Close cURL session
curl_close($ch);

// Set JSON content type header
header('Content-Type: application/json');

// Check if request was successful
if ($http_code !== 200) {
    die(json_encode([
        'error' => 'API request failed',
        'status' => $http_code,
        'response' => $response
    ]));
}

// Output response
echo $response;

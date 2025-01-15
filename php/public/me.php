<?php
require __DIR__ . '/../vendor/autoload.php';

error_log('me.php called');

// Connect to SQLite database
$db = new SQLite3(__DIR__ . '/../demo.db');

// Get access token from database
$result = $db->query('SELECT access_token FROM demo');
$row = $result->fetchArray(SQLITE3_ASSOC);

if (!$row || !isset($row['access_token'])) {
    die('No access token found. Please connect to Samsara first.');
}

$access_token = $row['access_token'];
error_log('Access token: ' . $access_token);

// Initialize cURL session
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

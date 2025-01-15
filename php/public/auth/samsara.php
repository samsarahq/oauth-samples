<?php
require __DIR__ . '/../../vendor/autoload.php';
session_start();

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

// Generate random state parameter for CSRF protection
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;

// Log the state parameter for debugging
error_log('OAuth state parameter: ' . $state);


// Build authorization URL
$params = [
    'client_id' => $_ENV['SAMSARA_CLIENT_ID'],
    'state' => $state,
    'response_type' => 'code',
    'redirect_uri' => 'http://localhost:5000/auth/samsara_callback.php'
];

$auth_url = 'https://api.samsara.com/oauth2/authorize?' . http_build_query($params);

// Redirect to Samsara's authorization endpoint
header('Location: ' . $auth_url);
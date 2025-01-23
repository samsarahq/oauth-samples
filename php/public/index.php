<?php
require __DIR__ . '/../vendor/autoload.php';

session_start();

// Get credentials from session
$credentials = $_SESSION['credentials'] ?? null;

// Get access token from credentials
if ($credentials && isset($credentials['access_token'])) {
    $access_token = $credentials['access_token'];
} else {
    $access_token = 'Access token not found';
}

?>

<!DOCTYPE html>
<html>
<body>
    <h1>Samsara OAuth 2.0 Example</h1>
    <h2>Access Token</h2>
    <pre><?= $access_token ?></pre>
    <p>
      <a href="/auth/samsara.php" class="button">Connect to Samsara</a><br />
      <a href="/me.php" class="button">Get User Info</a><br />
      <a href="/auth/samsara_refresh.php" class="button">Refresh Token</a><br />
      <a href="/auth/samsara_revoke.php" class="button">Revoke Token</a><br />
    </p>
</body>
</html>

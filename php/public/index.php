<?php
require __DIR__ . '/../vendor/autoload.php';

// Find or create new SQLite database
$db = new SQLite3(__DIR__ . '/../demo.db');

// Find or create demo table with access_token and refresh_token columns
$db->exec('
    CREATE TABLE IF NOT EXISTS demo (
        access_token TEXT,
        refresh_token TEXT
    )
');

// Get access token from database
$result = $db->query('SELECT access_token FROM demo');
$row = $result->fetchArray(SQLITE3_ASSOC);

// Get access token from database
if ($row && isset($row['access_token'])) {
    $access_token = $row['access_token'];
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

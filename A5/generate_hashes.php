<?php
// ============================================================
//  generate_hashes.php
//  Run once:  http://localhost/generate_hashes.php
//
//  This script generates bcrypt hashes for plain passwords
//  and outputs INSERT statements you can paste into phpMyAdmin
//  (or run directly below via mysqli).
// ============================================================

// ----- 1. Define credentials to hash -----
$credentials = [
    ['username' => 'user1', 'password' => 'pass1'],
    ['username' => 'admin', 'password' => 'admin123'],
];

echo "<pre style='font-family:monospace; background:#111; color:#0f0;
      padding:20px; font-size:0.95rem; line-height:1.8'>";
echo "-- Paste these INSERT statements into phpMyAdmin for lab5_secure\n\n";
echo "USE lab5_secure;\n";
echo "DELETE FROM users;\n\n";

foreach ($credentials as $c) {
    $hash = password_hash($c['password'], PASSWORD_BCRYPT, ['cost' => 12]);
    echo "INSERT INTO users (username, password) VALUES ('{$c['username']}', '$hash');\n";
}

echo "\n-- Done!\n</pre>";

// ----- 2. Optionally auto-insert into lab5_secure -----
// Uncomment the block below to auto-populate the secure DB
/*
$conn = new mysqli("localhost", "root", "", "lab5_secure");
if ($conn->connect_error) { die("Connection failed: " . $conn->connect_error); }
$conn->query("DELETE FROM users");
foreach ($credentials as $c) {
    $hash = password_hash($c['password'], PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $c['username'], $hash);
    $stmt->execute();
    $stmt->close();
}
$conn->close();
echo "<p style='color:lime; font-family:monospace;'>&#x2705; Users inserted into lab5_secure!</p>";
*/
?>

<?php
// ============================================================
//  SECURE connection.php
//  Uses PDO with exception-based error handling.
//  Errors are NOT exposed to the user.
// ============================================================

$host   = "localhost";
$dbname = "lab5_secure";    // Separate DB with hashed passwords
$dbuser = "root";
$dbpass = "";

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $dbuser,
        $dbpass,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,  // Force real prepared statements
        ]
    );
} catch (PDOException $e) {
    // Log error server-side only — NEVER expose to the browser
    error_log("DB Connection Error: " . $e->getMessage());
    die("A server error occurred. Please contact the administrator.");
}
?>

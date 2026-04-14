<?php
// ============================================================
//  SECURE authentication.php
//  Fixes Applied:
//    1. Prepared statements (parameterized queries)
//    2. Password hashing via password_hash / password_verify
//    3. Input validation and length checks
//    4. No SQL errors exposed to the browser
//    5. Session regeneration to prevent session fixation
// ============================================================

session_start();
require 'connection.php';

// ---- Defense 1: Accept only POST requests ----
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit();
}

// ---- Defense 2: Input validation ----
$username = trim($_POST['username'] ?? '');
$password = trim($_POST['password'] ?? '');

// Reject empty inputs
if (empty($username) || empty($password)) {
    header("Location: index.php?error=1");
    exit();
}

// Reject overly long inputs (prevents buffer-overflow-style abuse)
if (strlen($username) > 50 || strlen($password) > 100) {
    header("Location: index.php?error=1");
    exit();
}

// Reject usernames with non-alphanumeric characters (strict whitelist)
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    header("Location: index.php?error=1");
    exit();
}

// ---- Defense 3: Prepared statement — username is a parameter, not interpolated ----
try {
    $stmt = $pdo->prepare("SELECT username, password FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();
} catch (PDOException $e) {
    // Log server-side, never expose to user
    error_log("Query Error: " . $e->getMessage());
    header("Location: index.php?error=1");
    exit();
}

// ---- Defense 4: password_verify() — compare against hashed password ----
// If no user found OR password does not match, fail with a generic message
if (!$user || !password_verify($password, $user['password'])) {
    header("Location: index.php?error=1");
    exit();
}

// ---- Defense 5: Regenerate session ID to prevent session fixation ----
session_regenerate_id(true);

$_SESSION['loggedin']  = true;
$_SESSION['username']  = $user['username'];

// Show success page — no DB data / query details leaked
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Successful | Secure App</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            min-height: 100vh; background: #0d1117;
            display: flex; align-items: center; justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #e6edf3;
        }
        .box {
            background: #161b22; border: 1px solid #30a14e;
            border-radius: 12px; padding: 40px 50px; text-align: center;
            max-width: 420px; width: 100%;
            box-shadow: 0 8px 32px rgba(48,161,78,0.15);
        }
        h1 { color: #30a14e; font-size: 2rem; margin-bottom: 10px; }
        p { color: #8b949e; margin-bottom: 24px; }
        strong { color: #e6edf3; }
        a {
            display: inline-block; padding: 10px 24px;
            background: #21262d; color: #e6edf3; text-decoration: none;
            border-radius: 6px; font-size: 0.9rem; border: 1px solid #30363d;
        }
        a:hover { background: #30363d; }
        .note {
            margin-top: 20px; padding: 10px; background: rgba(48,161,78,0.08);
            border-radius: 6px; font-size: 0.8rem; color: #30a14e;
        }
    </style>
</head>
<body>
<div class="box">
    <h1>&#x2705; Welcome!</h1>
    <p>Logged in as <strong><?= htmlspecialchars($_SESSION['username']) ?></strong></p>
    <a href="index.php?logout=1">Logout</a>
    <div class="note">
        &#x1F512; This page does not display raw query output,<br>
        database contents, or error messages.
    </div>
</div>
</body>
</html>
<?php
// Destroy session on logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php?logout=1");
    exit();
}
?>

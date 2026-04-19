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
        :root {
            --primary: #10b981;
            --primary-dark: #059669;
            --primary-light: #34d399;
            
            --bg-primary: #0a0e27;
            --bg-secondary: #1a1f3a;
            --bg-tertiary: #232d4b;
            
            --text-primary: #e0e8ff;
            --text-secondary: #a8b2d1;
            --text-muted: #6b7896;
            
            --border-light: #3a4a6b;
        }

        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            min-height: 100vh;
            background: linear-gradient(135deg, var(--bg-primary) 0%, #0d1228 50%, var(--bg-secondary) 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            color: var(--text-primary);
            padding: 20px;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at 20% 50%, rgba(16, 185, 129, 0.03) 0%, transparent 50%),
                        radial-gradient(circle at 80% 80%, rgba(50, 150, 255, 0.03) 0%, transparent 50%);
            pointer-events: none;
            z-index: -1;
        }

        .box {
            background: var(--bg-secondary);
            border: 1px solid var(--border-light);
            border-radius: 16px;
            padding: 48px 44px;
            text-align: center;
            max-width: 460px;
            width: 100%;
            box-shadow: 
                0 20px 60px rgba(16, 185, 129, 0.1),
                0 0 40px rgba(50, 150, 255, 0.05),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            animation: slideInUp 0.5s ease-out;
            position: relative;
            overflow: hidden;
        }

        @keyframes slideInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .box::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--primary), transparent);
            opacity: 0.5;
        }

        h1 {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }

        p {
            color: var(--text-secondary);
            margin-bottom: 28px;
            font-size: 1rem;
            line-height: 1.6;
        }

        strong {
            color: var(--text-primary);
            font-weight: 700;
        }

        a {
            display: inline-block;
            padding: 14px 32px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: #fff;
            text-decoration: none;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
            position: relative;
            overflow: hidden;
            border: none;
            cursor: pointer;
        }

        a::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }

        a:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
        }

        a:active {
            transform: translateY(0);
        }

        a:hover::before {
            width: 300px;
            height: 300px;
        }

        .note {
            margin-top: 28px;
            padding: 16px 18px;
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--bg-primary) 100%);
            border: 1px solid var(--border-light);
            border-radius: 8px;
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        @media (max-width: 600px) {
            .box {
                padding: 36px 28px;
                border-radius: 12px;
            }

            h1 {
                font-size: 1.5rem;
            }

            p {
                font-size: 0.95rem;
            }
        }
    </style>
</head>
<body>
<div class="box">
    <h1 style="font-size: 1.8rem; font-weight: 700; margin-bottom: 24px; text-align: center; background: linear-gradient(135deg, #10b981 0%, #34d399 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">Secure App</h1>
    <h2 style="font-size: 1.4rem; font-weight: 700; margin-bottom: 16px; text-align: center;">Welcome</h2>
    <p>Logged in as <strong><?= htmlspecialchars($_SESSION['username']) ?></strong></p>
    <a href="index.php?logout=1">Logout</a>
    <div class="note">
         This page does not display raw query output,<br>
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

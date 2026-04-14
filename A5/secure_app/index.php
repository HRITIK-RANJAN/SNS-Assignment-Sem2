<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login | Lab 5</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            min-height: 100vh;
            background: #0d1117;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #e6edf3;
        }
        .login-wrapper { width: 100%; max-width: 420px; padding: 20px; }
        .login-box {
            background: #161b22;
            border: 1px solid #30a14e;
            border-radius: 12px;
            padding: 36px 40px;
            box-shadow: 0 8px 32px rgba(48, 161, 78, 0.12);
        }
        .login-header { text-align: center; margin-bottom: 28px; }
        .login-header h1 { font-size: 1.6rem; color: #30a14e; margin-bottom: 6px; }
        .login-header p { font-size: 0.85rem; color: #888; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 6px; font-size: 0.9rem; color: #aaa; }
        .form-group input {
            width: 100%; padding: 12px 14px;
            background: #0d1117; border: 1px solid #30363d;
            border-radius: 6px; color: #e6edf3; font-size: 0.95rem;
            transition: border-color 0.2s;
        }
        .form-group input:focus { outline: none; border-color: #30a14e; }
        .btn-login {
            width: 100%; padding: 13px; background: #30a14e;
            color: #fff; border: none; border-radius: 6px;
            font-size: 1rem; font-weight: 600; cursor: pointer;
            transition: background 0.2s; margin-top: 6px;
        }
        .btn-login:hover { background: #238636; }
        .alert {
            padding: 12px 14px; border-radius: 6px;
            margin-bottom: 20px; font-size: 0.9rem; line-height: 1.5;
        }
        .alert-error {
            background: rgba(248,81,73,0.15);
            border: 1px solid #f85149; color: #f85149;
        }
        .alert-success {
            background: rgba(48,161,78,0.12);
            border: 1px solid #30a14e; color: #30a14e;
        }
        .badge {
            display: inline-block; padding: 3px 8px;
            background: rgba(48,161,78,0.2); color: #30a14e;
            border-radius: 4px; font-size: 0.75rem; font-weight: 600;
            margin-left: 6px; vertical-align: middle;
        }
        .btn-logout {
            display: inline-block; margin-top: 20px; padding: 10px 20px;
            background: #21262d; color: #e6edf3; text-decoration: none;
            border-radius: 6px; font-size: 0.9rem;
        }
    </style>
</head>
<body>

<div class="login-wrapper">
    <div class="login-box">
        <div class="login-header">
            <h1>&#x1F512; Secure App <span class="badge">PROTECTED</span></h1>
            <p>SQL Injection Defense &mdash; Lab 5</p>
        </div>

        <?php if (isset($_GET['error'])): ?>
            <div class="alert alert-error">
                &#x274C; Invalid username or password.
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['logout'])): ?>
            <div class="alert alert-success">
                You have been logged out successfully.
            </div>
        <?php endif; ?>

        <form action="authentication.php" method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="Enter username"
                    maxlength="50"
                    autocomplete="off"
                    required
                />
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter password"
                    maxlength="100"
                    autocomplete="off"
                    required
                />
            </div>

            <button type="submit" class="btn-login">Login Securely</button>
        </form>
    </div>
</div>

</body>
</html>

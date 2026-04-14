<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Login | Lab 5</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="login-wrapper">
    <div class="login-box">
        <div class="login-header">
            <h1>&#x26A0; Vulnerable App</h1>
            <p>SQL Injection Demo &mdash; Lab 5</p>
        </div>

        <?php if (isset($_GET['error'])): ?>
            <div class="alert alert-error">
                &#x274C; Invalid username or password.
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['logout'])): ?>
            <div class="alert alert-info">
                You have been logged out.
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
                    autocomplete="off"
                />
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter password"
                    autocomplete="off"
                />
            </div>

            <button type="submit" class="btn-login">Login</button>
        </form>

        <div class="hint-box">
            <strong>Test credentials:</strong><br>
            user1 / pass1<br>
            admin / admin123
        </div>
    </div>
</div>

</body>
</html>

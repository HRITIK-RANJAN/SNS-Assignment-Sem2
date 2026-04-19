<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login | Lab 5</title>
    <style>
        /* ============================================
           Enhanced Secure App Styles (Green Theme)
           ============================================ */

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
            
            --border-color: #2d3f5b;
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
            line-height: 1.6;
            overflow-x: hidden;
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

        .login-wrapper {
            width: 100%;
            max-width: 460px;
            padding: 20px;
            margin: auto;
        }

        .login-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border-light);
            border-radius: 16px;
            padding: 48px 44px;
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

        .login-box::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--primary), transparent);
            opacity: 0.5;
        }

        .login-header {
            text-align: center;
            margin-bottom: 36px;
        }

        .login-header h1 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        .login-header p {
            font-size: 0.95rem;
            color: var(--text-secondary);
            font-weight: 500;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .badge {
            display: inline-block;
            padding: 6px 12px;
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.3), rgba(16, 185, 129, 0.15));
            color: var(--primary-light);
            border: 1px solid rgba(16, 185, 129, 0.4);
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 700;
            margin-left: 8px;
            vertical-align: middle;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .form-group {
            margin-bottom: 24px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .form-group input {
            width: 100%;
            padding: 13px 16px;
            background: var(--bg-primary);
            border: 1.5px solid var(--border-color);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .form-group input::placeholder {
            color: var(--text-muted);
        }

        .form-group input:hover {
            border-color: var(--border-light);
            background: linear-gradient(var(--bg-primary), var(--bg-primary)) padding-box,
                        linear-gradient(135deg, var(--border-color), var(--primary-dark)) border-box;
        }

        .form-group input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1),
                        inset 0 1px 2px rgba(255, 255, 255, 0.05);
            background: linear-gradient(var(--bg-primary), var(--bg-primary)) padding-box,
                        linear-gradient(135deg, var(--primary), var(--primary-light)) border-box;
        }

        .btn-login {
            width: 100%;
            padding: 14px 16px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }

        .btn-login::before {
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

        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
        }

        .btn-login:active {
            transform: translateY(0);
        }

        .btn-login:hover::before {
            width: 300px;
            height: 300px;
        }

        .alert {
            padding: 16px 18px;
            border-radius: 10px;
            margin-bottom: 24px;
            font-size: 0.95rem;
            line-height: 1.6;
            border: 1.5px solid;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: slideInDown 0.4s ease-out;
        }

        @keyframes slideInDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .alert-error {
            background: linear-gradient(135deg, rgba(248, 81, 73, 0.15), rgba(248, 81, 73, 0.08));
            border-color: rgba(248, 81, 73, 0.4);
            color: #ff8b7f;
        }

        .alert-success {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(16, 185, 129, 0.08));
            border-color: rgba(16, 185, 129, 0.4);
            color: var(--primary-light);
        }

        .btn-logout {
            display: inline-block;
            margin-top: 24px;
            padding: 12px 24px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            text-decoration: none;
            border: 1.5px solid var(--border-light);
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 600;
            transition: all 0.3s ease;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .btn-logout:hover {
            background: var(--primary);
            border-color: var(--primary);
            color: #fff;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
            transform: translateY(-2px);
        }

        @media (max-width: 600px) {
            .login-wrapper {
                max-width: 100%;
                padding: 16px;
            }
            
            .login-box {
                padding: 36px 28px;
                border-radius: 12px;
            }
            
            .login-header h1 {
                font-size: 1.5rem;
            }
            
            .login-header p {
                font-size: 0.85rem;
            }
            
            .form-group input {
                padding: 12px 14px;
            }
            
            .btn-login {
                padding: 13px 14px;
            }
            
            .alert {
                flex-direction: column;
                align-items: flex-start;
            }
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

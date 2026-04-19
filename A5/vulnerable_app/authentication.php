<?php
// ============================================================
//  VULNERABLE authentication.php
//  WARNING: Intentionally insecure for Lab 5 demonstration.
//           DO NOT use this code in production.
// ============================================================

session_start();
require 'connection.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit();
}

// Directly use raw user input — NO sanitisation (intentional)
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

function build_vulnerable_query($input_username, $input_password)
{
      return "SELECT * FROM users WHERE username='$input_username' AND password='$input_password'";
}

function looks_like_injection($value)
{
      return preg_match('/(--|#|\/\*|\*\/|\'|\"|\bOR\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)/i', $value) === 1;
}

function execute_vulnerable_sql($conn, $sql)
{
      $response = [
            'ok' => false,
            'rows' => [],
            'affected_rows' => 0,
            'error' => ''
      ];

      try {
            // Intentionally unsafe: allow stacked statements for SQLi demo.
            if (!mysqli_multi_query($conn, $sql)) {
                  $response['error'] = mysqli_error($conn);
                  return $response;
            }

            $response['ok'] = true;

            do {
                  $current_result = mysqli_store_result($conn);

                  if ($current_result instanceof mysqli_result) {
                        while ($row = mysqli_fetch_assoc($current_result)) {
                              $response['rows'][] = $row;
                        }
                        mysqli_free_result($current_result);
                  } else {
                        $affected = mysqli_affected_rows($conn);
                        if ($affected > 0) {
                              $response['affected_rows'] += $affected;
                        }
                  }

                  if (!mysqli_more_results($conn)) {
                        break;
                  }
            } while (mysqli_next_result($conn));

            if (mysqli_errno($conn)) {
                  $response['ok'] = false;
                  $response['error'] = mysqli_error($conn);
            }
      } catch (mysqli_sql_exception $e) {
            $response['error'] = $e->getMessage();
      }

      // Clear any pending results before next attempt.
      while (mysqli_more_results($conn) && mysqli_next_result($conn)) {
            $pending_result = mysqli_store_result($conn);
            if ($pending_result instanceof mysqli_result) {
                  mysqli_free_result($pending_result);
            }
      }

      return $response;
}

$is_injection_attempt = looks_like_injection($username) || looks_like_injection($password);

// -----------------------------------------------------------
// VULNERABLE QUERY — string interpolation, no prepared stmts
// Attack payloads work here, e.g.:
//   username: admin'--
//   username: ' OR '1'='1
//   username: ' UNION SELECT username,password FROM users--
// -----------------------------------------------------------
$attempts = [];
$attempts[] = [
      'username' => $username,
      'password' => $password,
      'label' => 'Original payload'
];

$dash_fixed_username = preg_replace('/--(?!\s)/', '-- ', $username);
$dash_fixed_password = preg_replace('/--(?!\s)/', '-- ', $password);
if ($dash_fixed_username !== $username || $dash_fixed_password !== $password) {
      $attempts[] = [
            'username' => $dash_fixed_username,
            'password' => $dash_fixed_password,
            'label' => 'Auto-added required space after -- comment marker'
      ];
}

$hash_comment_username = str_replace('--', '#', $username);
$hash_comment_password = str_replace('--', '#', $password);
if ($hash_comment_username !== $username || $hash_comment_password !== $password) {
      $attempts[] = [
            'username' => $hash_comment_username,
            'password' => $hash_comment_password,
            'label' => 'Auto-converted -- comment marker to # for MySQL compatibility'
      ];
}

$returned_rows = [];
$modified_rows = 0;
$executed_sql = '';
$execution_note = '';
$mysql_error = '';

foreach ($attempts as $attempt) {
      $executed_sql = build_vulnerable_query($attempt['username'], $attempt['password']);

      $query_result = execute_vulnerable_sql($conn, $executed_sql);
      if ($query_result['ok']) {
            $returned_rows = $query_result['rows'];
            $modified_rows = $query_result['affected_rows'];
            $execution_note = $attempt['label'];
            break;
      }

      $mysql_error = $query_result['error'];
}

$count = count($returned_rows);
$login_successful = $count > 0;
$modification_successful = $modified_rows > 0;

if ($login_successful) {
      $_SESSION['loggedin'] = true;
      $_SESSION['username'] = $username;
}

echo "<!DOCTYPE html><html><head>
        <link rel='stylesheet' href='style.css'>
        </head><body>";

// Display the raw query so the attack is visible in output
echo "<div style='
        font-family: \"Courier New\", monospace;
        background: linear-gradient(135deg, #1a2f3f 0%, #0d1f2d 100%);
        color: #10f981;
        padding: 16px;
        margin: 16px 16px 0;
        border-radius: 8px;
        border: 1.5px solid rgba(16, 249, 129, 0.3);
        box-shadow: 0 4px 12px rgba(16, 249, 129, 0.1), inset 0 1px 2px rgba(255, 255, 255, 0.05);
        font-size: 0.85rem;
        line-height: 1.6;
        overflow-x: auto;
      '>
        <strong style='color:#34d399; font-weight:700; text-transform:uppercase; letter-spacing:0.5px;'>
            Executed Query:
        </strong><br><br>
        <code style='color:#10f981;'>" . htmlspecialchars($executed_sql) . "</code>
        </div>";

echo "<div class='login-wrapper'><div class='login-box'>";
echo "<div class='login-header'><h1>&#x26A0; Vulnerable App</h1></div>";

if ($execution_note !== '' && $execution_note !== 'Original payload') {
      echo "<div class='alert alert-info'>
              &#x2139; <strong>Payload Normalized:</strong> " . htmlspecialchars($execution_note) . "
              </div>";
}

if ($login_successful || $modification_successful) {
      if ($is_injection_attempt) {
            if ($login_successful && $modification_successful) {
                  echo "<div class='alert alert-success'>
                          &#x2705; <strong>Injection Successful!</strong><br>
                          Authentication bypass and database modification both succeeded.
                          </div>";
            } elseif ($login_successful) {
                  echo "<div class='alert alert-success'>
                          &#x2705; <strong>Injection Successful!</strong><br>
                          Authentication bypass succeeded. Welcome, <em>" . htmlspecialchars($username) . "</em>
                          </div>";
            } else {
                  echo "<div class='alert alert-success'>
                          &#x2705; <strong>Injection Successful!</strong><br>
                          Database modification executed successfully.
                          </div>";
            }
      } else {
            echo "<div class='alert alert-success'>
                    &#x2705; <strong>Login Successful!</strong><br>
                    Welcome, <em>" . htmlspecialchars($username) . "</em>
                    </div>";
      }

      if ($login_successful) {
            echo "<h3 style='
                    color: #e0e8ff;
                    font-size: 1.1rem;
                    font-weight: 700;
                    margin-top: 28px;
                    margin-bottom: 14px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                  '>Rows Returned by Query</h3>";
            echo "<table class='result-table'>";
            echo "<tr><th>#</th><th>Username</th><th>Password</th></tr>";

            $row_num = 1;
            foreach ($returned_rows as $row) {
                  echo "<tr>
                          <td>" . $row_num++ . "</td>
                          <td>" . htmlspecialchars($row['username'] ?? $row[0] ?? 'N/A') . "</td>
                          <td>" . htmlspecialchars($row['password'] ?? $row[1] ?? 'N/A') . "</td>
                          </tr>";
            }
            echo "</table>";
      }

      if ($modification_successful) {
            echo "<div class='alert alert-info' style='margin-top:16px;'>
                    &#x2139; <strong>Database Modified:</strong> " . (int)$modified_rows . " row(s) affected by injected statement(s).
                    </div>";
      }

      echo "<a href='index.php?logout=1' class='btn-logout'>Logout</a>";
} else {
      if ($mysql_error !== '') {
            echo "<div class='alert alert-error'>
                    &#x274C; <strong>Query Failed:</strong><br>
                    " . htmlspecialchars($mysql_error) . "
                    </div>";
      } else {
            echo "<div class='alert alert-error'>
                    &#x274C; <strong>Login Failed:</strong><br>
                    No rows were returned by this payload.
                    </div>";
      }

      echo "<a href='index.php' class='btn-logout'>Try Another Payload</a>";
}

echo "</div></div></body></html>";

mysqli_close($conn);
?>

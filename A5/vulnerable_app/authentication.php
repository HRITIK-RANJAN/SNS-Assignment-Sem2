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
$username = $_POST['username'];
$password = $_POST['password'];

// -----------------------------------------------------------
// VULNERABLE QUERY — string interpolation, no prepared stmts
// Attack payloads work here, e.g.:
//   username: admin'--
//   username: ' OR '1'='1
//   username: ' UNION SELECT username,password FROM users--
// -----------------------------------------------------------
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";

// Display the raw query so the attack is visible in output
echo "<div style='font-family:monospace; background:#1e1e1e; color:#0f0;
      padding:10px; margin:10px; border-radius:6px;'>
      <strong style='color:#fff'>Executed Query:</strong><br>
      " . htmlspecialchars($sql) . "
      </div>";

$result = mysqli_query($conn, $sql);

// Also display any MySQL error (intentionally insecure)
if (!$result) {
    echo "<div style='color:red; font-family:monospace; padding:10px;'>
          MySQL Error: " . mysqli_error($conn) . "
          </div>";
    exit();
}

$count = mysqli_num_rows($result);

if ($count > 0) {
    $_SESSION['loggedin'] = true;
    $_SESSION['username'] = $username;

    // Fetch and display ALL returned rows (shows Union-based injection output)
    echo "<!DOCTYPE html><html><head>
          <link rel='stylesheet' href='style.css'>
          </head><body><div class='login-wrapper'><div class='login-box'>";

    echo "<div class='alert alert-success'>
          &#x2705; <strong>Login Successful!</strong><br>
          Welcome, <em>" . htmlspecialchars($username) . "</em>
          </div>";

    echo "<h3 style='color:#ccc; margin-top:20px;'>Rows Returned by Query</h3>";
    echo "<table class='result-table'>";
    echo "<tr><th>#</th><th>Username</th><th>Password</th></tr>";

    $row_num = 1;
    while ($row = mysqli_fetch_assoc($result)) {
        echo "<tr>
              <td>" . $row_num++ . "</td>
              <td>" . htmlspecialchars($row['username'] ?? $row[0] ?? 'N/A') . "</td>
              <td>" . htmlspecialchars($row['password'] ?? $row[1] ?? 'N/A') . "</td>
              </tr>";
    }
    echo "</table>";

    echo "<a href='index.php?logout=1' class='btn-logout'>Logout</a>";
    echo "</div></div></body></html>";

} else {
    header("Location: index.php?error=1");
    exit();
}

mysqli_close($conn);
?>

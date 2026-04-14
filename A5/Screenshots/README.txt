# Screenshots — Required Evidence

Place your screenshots in this folder before submission.
Rename each file exactly as listed below for easy evaluation.

## Required Screenshots

| Filename                              | What to Capture                                              |
|---------------------------------------|--------------------------------------------------------------|
| `01_normal_login_success.png`         | user1/pass1 login succeeding on vulnerable_app              |
| `02_auth_bypass_payload.png`          | Login form showing `' OR '1'='1' --` in username field      |
| `03_auth_bypass_success.png`          | Result page after bypass — shows rows returned              |
| `04_union_injection_payload.png`      | Login form with UNION payload entered                        |
| `05_union_injection_result.png`       | Result page showing both user records dumped                |
| `06_blind_injection_true.png`         | True condition — login succeeds                              |
| `06_blind_injection_false.png`        | False condition — login fails                                |
| `07_db_before_insert.png`             | phpMyAdmin SELECT * showing 2 users BEFORE insert attack     |
| `08_db_insert_payload.png`            | Login form with INSERT injection payload                    |
| `09_db_after_insert.png`              | phpMyAdmin SELECT * showing 3 users AFTER insert attack      |
| `10_db_before_update.png`             | phpMyAdmin showing admin password = admin123 BEFORE update   |
| `11_db_update_payload.png`            | Login form with UPDATE injection payload                    |
| `12_db_after_update.png`              | phpMyAdmin showing admin password = pwned AFTER update       |
| `13_secure_bypass_blocked.png`        | Bypass payload FAILING on secure_app (error message)        |
| `14_secure_union_blocked.png`         | UNION payload FAILING on secure_app                         |
| `15_secure_modify_blocked.png`        | INSERT/UPDATE payload FAILING on secure_app                 |

## How to Take Screenshots (Windows)
- Press `Win + Shift + S` for the snipping tool.
- Or use `Print Screen` and paste into Paint.
- Save all files as PNG.

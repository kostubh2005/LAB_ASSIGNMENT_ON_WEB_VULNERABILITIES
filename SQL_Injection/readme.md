# SQL Injection: Variant 1 (Authentication Bypass)

Cyber Security (IT-30001), Autumn 2026, IIIT Allahabad

**Owner:** [Kostubh], [Birla]

## Files

- `app_vulnerable.py`: login with the SQL injection flaw
- `app_secure.py`: same login with a parameterised query (fix)

## Setup
pip install flask
python app_vulnerable.py


Open `http://127.0.0.1:5000`. Test accounts: `admin / secret123`, `alice / alicepass`.

## Exploit

Username: `' OR '1'='1' -- ` (any password)

Result: logged in as admin without the password.

## Root Cause

User input is pasted into the SQL string, so it can change the query's meaning.

## Fix

`app_secure.py` uses placeholders:

```python
"SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
```

The same payload now shows "Invalid username or password."

## Other Mitigations (Theory)

- **Allow-list validation:** accept only expected characters.
- **Least privilege:** limit the database user's rights.
- **Safe errors:** don't show raw database errors.

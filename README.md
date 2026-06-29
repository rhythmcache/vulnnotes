# VulnNotes - Vulnerability Writeup

This document covers all four intentionally planted vulnerabilities in this web app: how each was exploited (verified against a real running instance, not just theorized), why it is dangerous, and how to fix it.

All exploitation below was run against a local instance only (`127.0.0.1:5000`) using `curl`. Do not run this app anywhere reachable by anyone other than yourself.

---

## 1. SQL Injection - Login Bypass

**Location:** `app.py`, `login()` route.

**Root cause:** the login query is built with an f-string that directly interpolates user input into SQL syntax instead of using parameterized queries:

```python
query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
cur = db.execute(query)
```

**Exploitation:** the textbook `' OR '1'='1` payload does not fully bypass this specific query. SQL's `AND` binds tighter than `OR`, so `username = '' OR '1'='1' AND password = 'x'` actually parses as `username = '' OR ('1'='1' AND password = 'x')`, and the password clause still has to match something. This is worth understanding precisely rather than just memorizing a payload. Injection has to account for the real shape of the query it lands in.

The payload that does work here uses a SQL line comment to discard the trailing password check entirely:

* Username: `alice' --`
* Password: (anything)

This produces:

```sql
SELECT id, username FROM users WHERE username = 'alice' --' AND password = '...'
```

Everything after `--` is a SQL comment, so the password check is never evaluated. Verified working:

```sh
curl -i -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=alice' --" \
  --data-urlencode "password=anything"
# -> HTTP 302, Set-Cookie: session_token=... (logged in as alice, no password needed)
```

**Fix:** use parameterized queries. Let the database driver handle escaping instead of building SQL via string interpolation:

```python
cur = db.execute(
    "SELECT id, username FROM users WHERE username = ? AND password = ?",
    (username, password),
)
```

This is the single most important fix in the whole app. Parameterized queries close off SQL injection structurally, not by trying to filter or escape specific dangerous characters, which is fragile and easy to get wrong.

---

## 2. IDOR - Viewing Other Users' Notes

**Location:** `app.py`, `view_note()` route.

**Root cause:** the note lookup checks only that a note with the given ID exists. It never checks that it belongs to the logged in user:

```python
cur = db.execute("SELECT id, title, content, owner_id FROM notes WHERE id = ?", (note_id,))
note = cur.fetchone()
# ... no check that note.owner_id == user.id ...
```

**Exploitation:** logged in as alice (user id 1), simply requesting a note ID known to belong to bob (user id 2) returns it in full:

```sh
curl -b alice_cookies.txt http://127.0.0.1:5000/notes/3
# -> 200 OK, returns "Bob's bank PIN reminder" owned by user id 2
```

Verified: the response confirms the leaked note's `owner_id` is 2, while the requesting session belongs to user 1. No authorization check exists between verifying the note exists and verifying ownership.

**Fix:** check ownership explicitly before returning the note:

```python
cur = db.execute(
    "SELECT id, title, content, owner_id FROM notes WHERE id = ?", (note_id,)
)
note = cur.fetchone()

if not note:
    return "Note not found", 404
if note[3] != user[0]:
    return "Forbidden", 403
```

More generally, any time an object is fetched by an ID that the client controls, the server must verify that the requesting user has permission to access that object. Existence and authorization are separate checks, and this bug comes from treating them as one.

---

## 3. Broken Authentication - Weak Session Tokens

**Location:** `app.py`, `generate_session_token()`.

**Root cause:** session tokens are 6 characters from a 36 character charset (`a-z0-9`) and are generated using Python's `random` module:

```python
def generate_session_token():
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(6))
```

**Why this is broken, quantified:** the total keyspace is 36^6 = 2,176,782,336, about 2.2 billion possible tokens. That sounds large in isolation, but with no rate limiting, an attacker can attempt tokens directly against the cookie value using multithreaded brute force. No password is needed if a valid token is found.

There is also a second problem. `random` is a Mersenne Twister PRNG, which is not cryptographically secure. Given enough output, its internal state can be predicted in principle. A proper CSPRNG avoids this entirely.

On top of that, tokens never expire and are not tied to any session metadata. A leaked or guessed token remains valid indefinitely.

**Fix:** use a cryptographically secure random source and a much larger token space, along with expiry:

```python
import secrets

def generate_session_token():
    return secrets.token_hex(32)  # 256 bits of entropy
```

A production app should also include expiry timestamps and validation on every request. Using signed or framework managed sessions is strongly preferred over hand rolled token systems.

---

## 4. Stored XSS - Unescaped Note Content

**Location:** `templates/view_note.html`.

**Root cause:** the note content is rendered with the `|safe` filter, which disables Jinja2's default HTML escaping:

```html
{{ note[2]|safe }}
```

**Exploitation:** since users can store arbitrary content, a note containing:

```html
<script>alert('xss-poc')</script>This is a malicious note.
```

is rendered directly into the HTML:

```sh
curl -b alice_cookies.txt http://127.0.0.1:5000/notes/4
# -> <div class="note-content">
#        <script>alert('xss-poc')</script>This is a malicious note.
#    </div>
```

A real browser executes this script. Combined with weak session tokens, an attacker could replace the alert with code that sends `document.cookie` to a remote server, stealing session tokens when a victim views the note. This turns the XSS into full account takeover.

**Fix:** remove `|safe`. Jinja2 escapes content by default:

```html
{{ note[2] }}
```

If rich text is required, sanitize input using an allowlist based HTML sanitizer such as `bleach`. Never trust raw user input as safe HTML.

---

## Chained Impact

These vulnerabilities become significantly more dangerous when combined. A realistic attack chain:

1. An attacker registers an account.
2. The attacker creates a note containing a cookie stealing XSS payload.
3. Due to the IDOR bug, that note is accessible by ID without ownership checks.
4. A victim views the note, and their session token is exfiltrated.
5. The attacker uses the stolen token to take over the account.

Fixing any one issue weakens the chain, but fixing all of them is necessary to address the underlying design problem. User input was trusted by default instead of being validated, escaped, or authorized at every boundary.

# VulnNotes — Vulnerability Writeup

This document covers all four intentionally planted vulnerabilities in
this app: how each was exploited (verified against a real running
instance, not just theorized), why it's dangerous, and how to fix it.

All exploitation below was run against a local instance only
(`127.0.0.1:5000`) using `curl`. Do not run this app anywhere reachable by
anyone other than yourself.

---

## 1. SQL Injection — Login Bypass

**Location:** `app.py`, `login()` route.

**Root cause:** the login query is built with an f-string that directly
interpolates user input into SQL syntax, instead of using parameterized
queries:

```python
query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
cur = db.execute(query)
```

**Exploitation:** the textbook `' OR '1'='1` payload does **not** fully
bypass this specific query — SQL's `AND` binds tighter than `OR`, so
`username = '' OR '1'='1' AND password = 'x'` actually parses as
`username = '' OR ('1'='1' AND password = 'x')`, and the password clause
still has to match something. This is worth understanding precisely
rather than just memorizing a payload: injection has to account for the
real shape of the query it lands in.

The payload that does work here uses a SQL line-comment to discard the
trailing password check entirely:

- Username: `alice' --`
- Password: (anything)

This produces:

```sql
SELECT id, username FROM users WHERE username = 'alice' --' AND password = '...'
```

Everything after `--` is a SQL comment, so the password check is never
evaluated. Verified working:

```sh
curl -i -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=alice' --" \
  --data-urlencode "password=anything"
# -> HTTP 302, Set-Cookie: session_token=... (logged in as alice, no password needed)
```

**Fix:** use parameterized queries — let the database driver handle
escaping, rather than building SQL via string interpolation:

```python
cur = db.execute(
    "SELECT id, username FROM users WHERE username = ? AND password = ?",
    (username, password),
)
```

This is the single most important fix in the whole app: parameterized
queries close off SQL injection structurally, not by trying to filter or
escape specific dangerous characters (which is fragile and easy to miss a
case for).

---

## 2. IDOR — Viewing Other Users' Notes

**Location:** `app.py`, `view_note()` route.

**Root cause:** the note lookup checks only that a note with the given ID
exists, never that it belongs to the logged-in user:

```python
cur = db.execute("SELECT id, title, content, owner_id FROM notes WHERE id = ?", (note_id,))
note = cur.fetchone()
# ... no check that note.owner_id == user.id ...
```

**Exploitation:** logged in as alice (user id 1), simply requesting a
note ID known to belong to bob (user id 2) returns it in full:

```sh
curl -b alice_cookies.txt http://127.0.0.1:5000/notes/3
# -> 200 OK, returns "Bob's bank PIN reminder" — owned by user id 2
```

Verified: the response itself confirms the leaked note's `owner_id` is 2,
while the requesting session belongs to user 1. No authorization check
exists between "is this a valid note ID" and "does this note belong to
the requester."

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

More generally: any time an object is fetched by an ID that the client
controls (URL parameter, form field, etc.), the server must verify the
requesting user actually has permission to access that specific object —
existence and authorization are two separate checks, and this bug comes
from collapsing them into one.

---

## 3. Broken Authentication — Weak Session Tokens

**Location:** `app.py`, `generate_session_token()`.

**Root cause:** session tokens are 6 characters from a 36-character
charset (`a-z0-9`), generated with Python's `random` module:

```python
def generate_session_token():
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(6))
```

**Why this is broken, quantified:** the total keyspace is 36^6 =
2,176,782,336 — about 2.2 billion possible tokens. That sounds large in
isolation, but with no rate limiting on the login or any other endpoint,
an attacker can attempt tokens directly against the live cookie value (no
password needed at all if a valid token is found) using straightforward
multithreaded brute force. There's also a second, independent problem:
`random` is a Mersenne Twister PRNG, which is not cryptographically
secure — given enough observed output, its internal state is in
principle predictable, which a true CSPRNG avoids entirely. On top of
that, tokens never expire and have no per-session secret tying them to
anything else, so a leaked or guessed token is valid indefinitely.

**Fix:** use a cryptographically secure random source and a much larger
token space, plus expiry:

```python
import secrets

def generate_session_token():
    return secrets.token_hex(32)  # 256 bits of entropy, CSPRNG-backed
```

A production app would also want token expiry (store an `expires_at`
timestamp and check it on every request), and ideally signed/stateless
tokens (e.g. JWT with a server-side secret) or framework-managed sessions
(e.g. Flask's built-in `session` object, which signs cookie contents)
rather than hand-rolled token storage in a plain database column.

---

## 4. Stored XSS — Unescaped Note Content

**Location:** `templates/view_note.html`.

**Root cause:** the note's content is rendered with the `|safe` filter,
which disables Jinja2's default HTML autoescaping for that value:

```html
{{ note[2]|safe }}
```

**Exploitation:** since any logged-in user can write a note with
arbitrary content, storing a note with this body:

```html
<script>alert('xss-poc')</script>This is a malicious note.
```

and then viewing it back returns the raw, unescaped tag directly in the
HTML response:

```sh
curl -b alice_cookies.txt http://127.0.0.1:5000/notes/4
# -> <div class="note-content">
#        <script>alert('xss-poc')</script>This is a malicious note.
#    </div>
```

A real browser loading this page executes that script. In combination
with vulnerability 3 (weak session tokens stored in a plain, readable
cookie), a real attack here would replace the proof-of-concept `alert()`
with something like sending document.cookie to an attacker-controlled
endpoint, exfiltrating the victim's session token to an attacker the
moment they view the malicious note — turning this single XSS bug into
full session takeover for whoever views it, combined with the IDOR bug
potentially making the malicious note viewable by anyone, not just its
author.

**Fix:** remove `|safe`. Jinja2 autoescapes by default, so simply
rendering the value normally is enough:

```html
{{ note[2] }}
```

If rich text in notes is genuinely a desired feature, the correct
approach is sanitizing the HTML through an allowlist-based sanitizer
(e.g. the `bleach` library) before storage or rendering — never trusting
user input to be safe HTML by default.

---

## Chained Impact

These four bugs are worse together than alone. A realistic attack chain:

1. An attacker registers their own account (registration is open to
   anyone, by design of a normal notes app).
2. The attacker creates a note containing the cookie-stealing XSS payload
   from #4.
3. Because of the IDOR bug (#2), that note is viewable by note ID alone —
   no ownership check stops another logged-in user from opening it if
   they're given (or guess) the ID.
4. When a victim views that note, their session token (weak per #3) is
   exfiltrated to the attacker.
5. The attacker now has full account takeover, no password needed.

Fixing any single one of these breaks the chain, but fixing all four is
what actually closes the underlying design problem: every user input
(query parameters, form fields, note content) was trusted by default
instead of being validated, escaped, or checked for authorization at each
boundary.

"""
this application contains four intentionally planted vulnerabilities, each
marked inline with a "vulnerability:" comment. please don't deploy this anywhere
reachable by anyone except yourself on a trusted local network . this is
made only for security learning/demo purpose, not for any real use.

see vulnerabilities.md for full writeup how each bug can be exploited,
why it is dangerous, and how to fix it (fixed version of each
function is also included for comparison).
"""


from flask import Flask, request, redirect, render_template, make_response, g
import sqlite3
import os
import random
import string

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()



# vulnerability 3 broken authentication due to predictable session tokens
# session tokens here are generated using a very small character set and
# short length. also it uses python's `random` module, which is not meant
# for security use (it uses mersenne twister, not a cryptographically
# secure random generator).
#
# on top of that, the token is stored directly in a plain cookie without
# any signing, so client can easily edit it from browser side. there is
# no expiry, no per-session secret, and no proper server-side validation
# apart from checking whether the token exists in the users table.
#
# because of this, an attacker can try guessing or brute forcing valid
# tokens. since the tokens are short and have low randomness, finding a
# valid one becomes much easier. once a valid token is found, attacker
# can log in as that user without ever knowing the actual password.

def generate_session_token():
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(6))


def get_logged_in_user():
    token = request.cookies.get("session_token")
    if not token:
        return None
    db = get_db()
    cur = db.execute(
        "SELECT id, username FROM users WHERE session_token = ?", (token,)
    )
    return cur.fetchone()


@app.route("/")
def index():
    user = get_logged_in_user()
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already taken")
        return redirect("/login")
    return render_template("register.html", error=None)




# vulnerability 1 sql injection in login
# username and password are directly inserted into the sql query using
# an f-string instead of using proper parameterized queries. because of
# this, user input becomes part of the sql statement itself, which can
# allow an attacker to change the intended query logic.
#
# one important thing to understand is that not every famous sqli payload
# works everywhere. many people remember "' or '1'='1" and try it blindly,
# but whether it works or not depends on how the query is actually written.
#
# in this case, sql operator precedence matters. `and` has higher priority
# than `or`, so the query does not behave the way beginners usually expect.
# because of that, a simple "' or '1'='1" style payload may not be enough to
# bypass authentication here.
#
# the real issue is that attackern controlled input can modify the query
# structure. by injecting sql syntax that comments out the remaining part
# of the statement, the password verification can be skipped completely.

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()

        query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
        cur = db.execute(query)
        user = cur.fetchone()

        if user:
            token = generate_session_token()
            db.execute(
                "UPDATE users SET session_token = ? WHERE id = ?", (token, user[0])
            )
            db.commit()
            resp = make_response(redirect("/"))
            resp.set_cookie("session_token", token)
            return resp
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    user = get_logged_in_user()
    if user:
        db = get_db()
        db.execute("UPDATE users SET session_token = NULL WHERE id = ?", (user[0],))
        db.commit()
    resp = make_response(redirect("/"))
    resp.delete_cookie("session_token")
    return resp


@app.route("/notes")
def my_notes():
    user = get_logged_in_user()
    if not user:
        return redirect("/login")
    db = get_db()
    cur = db.execute("SELECT id, title FROM notes WHERE owner_id = ?", (user[0],))
    notes = cur.fetchall()
    return render_template("notes.html", notes=notes, user=user)


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    user = get_logged_in_user()
    if not user:
        return redirect("/login")

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        db = get_db()
        db.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
            (user[0], title, content),
        )
        db.commit()
        return redirect("/notes")

    return render_template("new_note.html", user=user)



# VULNERABILITY 2: IDOR (Insecure Direct Object Reference)

# this endpoint fetches a note purely by its numeric ID, with no check
# that the note actually belongs to the logged-in user. Any logged-in
# user (or, combined with vulnerability 3, anyone who can forge/guess a
# session token) can view ANY note by simply changing the number in the
# URL  eg visiting /notes/3 while logged in as alice (id 1) still
# returns bob's note, because ownership is never checked.

@app.route("/notes/<int:note_id>")
def view_note(note_id):
    user = get_logged_in_user()
    if not user:
        return redirect("/login")

    db = get_db()
    cur = db.execute("SELECT id, title, content, owner_id FROM notes WHERE id = ?", (note_id,))
    note = cur.fetchone()

    if not note:
        return "Note not found", 404


# vulnerability 4: stored xss
# the note's `content` field is sent to the template and rendered using
# jinja2's `|safe` filter. this tells jinja2 not to escape html special
# characters and instead render the content exactly as provided.
#
# since note content is completely user-controlled, anyone can create a
# note containing html or javascript code. when another user later opens
# that note, the browser will treat the injected code as part of the page
# and execute it automatically.
#
# this is called stored xss because the malicious payload is stored in the
# database and keeps affecting every user who views the note. unlike
# reflected xss, the attacker only needs to submit the payload once.
#
# the impact can be serious. malicious javascript can read page content,
# perform actions on behalf of the victim, modify the interface, or steal
# sensitive information available to browser-side code. when combined with
# other weaknesses in the application, a stored xss bug can often lead to
# full account compromise.


    return render_template("view_note.html", note=note, user=user)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
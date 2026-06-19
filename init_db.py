"""
Sets up a fresh SQLite database for the vulnerable notes app, with two
seed users and a few notes. Run this once before starting the app, or
whenever you want to reset to a clean state.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")


def init():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            session_token TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """
    )

    # Seed users. Passwords are stored in plaintext here, which is itself
    # part of the deliberate "broken auth" category for this app  see
    # VULNERABILITIES.md for the full writeup of every issue and its fix.
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("alice", "alicepassword123"),
    )
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("bob", "bobsecurepass456"),
    )

    cur.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (1, "Alice's shopping list", "milk, eggs, bread"),
    )
    cur.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (1, "Alice's private thoughts", "I think Bob is planning a surprise party for me."),
    )
    cur.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (2, "Bob's bank PIN reminder", "PIN is definitely not 4729, do not write this down"),
    )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")
    print("Seed users: alice/alicepassword123, bob/bobsecurepass456")


if __name__ == "__main__":
    init()
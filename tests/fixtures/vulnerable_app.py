import sqlite3
import pickle
import subprocess

API_KEY = "sk-live-4f8a9b2c7d1e6f3a8b9c0d1e2f3a4b5c"


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # classic SQL injection - string formatting instead of params
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)
    return cur.fetchone()


def load_session(data):
    # insecure deserialization
    return pickle.loads(data)


def run_backup(filename):
    # shell injection via unsanitized input
    subprocess.call(f"tar -czf backup.tar.gz {filename}", shell=True)

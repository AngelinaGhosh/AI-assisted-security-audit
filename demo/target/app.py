"""Sample web app used for the live demo.

It mixes genuinely vulnerable code with code that only *looks*
vulnerable to a pattern-matching scanner, so the AI triage step
has real work to do.
"""
import hashlib
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

API_KEY = "sk-live-9d2f7a1c4b8e6f0a3d5c7b9e1f2a4c6d"
PASSWORD_FIELD = "password"  # name of the HTML form field, not a secret


def get_user(username):
    conn = sqlite3.connect("app.db")
    # user input goes straight into the SQL string
    query = "SELECT * FROM users WHERE username = '%s'" % username
    return conn.execute(query).fetchone()


def count_rows():
    conn = sqlite3.connect("app.db")
    table = "users"  # fixed internal constant, never user input
    query = "SELECT COUNT(*) FROM %s" % table
    return conn.execute(query).fetchone()


@app.route("/session", methods=["POST"])
def load_session():
    # raw bytes from the request body are unpickled
    return str(pickle.loads(request.data))


@app.route("/backup")
def run_backup():
    filename = request.args.get("file", "")
    subprocess.call(f"tar -czf backup.tar.gz {filename}", shell=True)
    return "ok"


def disk_usage():
    # fixed command, no user input anywhere
    return subprocess.run("df -h /", shell=True, capture_output=True).stdout


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def cache_key(url):
    # only used to name a cache file, not for security
    return hashlib.md5(url.encode()).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

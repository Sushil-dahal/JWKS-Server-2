# JWKS Server with SQLite-backed private key storage.
# Endpoints:
#   POST /auth                   - Issue a signed JWT (use ?expired for an expired one)
#   GET  /.well-known/jwks.json  - Return valid public keys in JWKS format
# All other methods/paths return 405.

import base64
import datetime
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = "localhost"
PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

# Open and return a connection to the SQLite database
def get_db_connection():
    return sqlite3.connect(DB_FILE)


# Drop and recreate the keys table, then insert one valid and one expired key.
# Dropping on every startup guarantees the gradebot always finds fresh rows.
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS keys")
    cur.execute(
        "CREATE TABLE IF NOT EXISTS keys("
        "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
        "key BLOB NOT NULL,"
        "exp INTEGER NOT NULL"
        ")"
    )

    now = int(time.time())

    # Valid key — expires 1 hour from now
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cur.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (serialize_key(valid_key), now + 3600),
    )

    # Expired key — expired 1 hour ago
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cur.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (serialize_key(expired_key), now - 3600),
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Key serialisation helpers
# ---------------------------------------------------------------------------

# Serialise an RSA private key to PKCS1 PEM bytes (unencrypted)
def serialize_key(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# Deserialise a private key from PEM bytes
def deserialize_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


# ---------------------------------------------------------------------------
# DB query helpers — all use parameterised queries to prevent SQL injection
# ---------------------------------------------------------------------------

# Return (pem_bytes, kid) of one unexpired key, or (None, None)
def get_valid_key():
    conn = get_db_connection()
    cur = conn.cursor()
    now = int(time.time())
    cur.execute("SELECT key, kid FROM keys WHERE exp > ? LIMIT 1", (now,))
    row = cur.fetchone()
    conn.close()
    if row:
        return row[0], str(row[1])
    return None, None


# Return (pem_bytes, kid) of one expired key, or (None, None)
def get_expired_key():
    conn = get_db_connection()
    cur = conn.cursor()
    now = int(time.time())
    cur.execute("SELECT key, kid FROM keys WHERE exp <= ? LIMIT 1", (now,))
    row = cur.fetchone()
    conn.close()
    if row:
        return row[0], str(row[1])
    return None, None


# Return list of (pem_bytes, kid) for all unexpired keys
def get_all_valid_keys():
    conn = get_db_connection()
    cur = conn.cursor()
    now = int(time.time())
    cur.execute("SELECT key, kid FROM keys WHERE exp > ?", (now,))
    rows = cur.fetchall()
    conn.close()
    return [(row[0], str(row[1])) for row in rows]


# ---------------------------------------------------------------------------
# JWKS utility
# ---------------------------------------------------------------------------

# Convert a large integer to a Base64URL-encoded string (no padding)
def int_to_base64(value: int) -> str:
    value_hex = format(value, "x")
    # Ensure even number of hex digits
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class MyServer(BaseHTTPRequestHandler):

    # Suppress per-request console log lines
    def log_message(self, format, *args):  # noqa: A002
        pass

    # Handle GET — only /.well-known/jwks.json is supported
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            keys = []
            for pem_bytes, kid in get_all_valid_keys():
                key = deserialize_key(pem_bytes)
                numbers = key.private_numbers()
                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": keys}).encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    # Handle POST /auth
    # ?expired param -> sign JWT with expired key and past exp claim
    # no param       -> sign JWT with valid key and future exp claim
    def do_POST(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        use_expired = "expired" in params

        if use_expired:
            pem_bytes, kid = get_expired_key()
            exp_delta = datetime.timedelta(hours=-1)
        else:
            pem_bytes, kid = get_valid_key()
            exp_delta = datetime.timedelta(hours=1)

        # No suitable key found in DB
        if pem_bytes is None:
            self.send_response(500)
            self.end_headers()
            return

        key = deserialize_key(pem_bytes)
        payload = {
            "user": "username",
            "exp": datetime.datetime.utcnow() + exp_delta,
        }
        token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(token.encode("utf-8"))

    # Reject all other HTTP methods
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    server = HTTPServer((HOST, PORT), MyServer)
    print(f"Server running at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("Server stopped.")

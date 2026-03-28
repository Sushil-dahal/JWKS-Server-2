# Test suite for the JWKS server (main.py).
# Run with: pytest test_main.py -v --cov=main --cov-report=term-missing

import base64 as b64
import datetime
import os
import sqlite3
import threading
import time
import unittest
from http.server import HTTPServer
from unittest.mock import patch

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

from main import (
    MyServer,
    deserialize_key,
    get_all_valid_keys,
    get_expired_key,
    get_valid_key,
    init_db,
    int_to_base64,
    serialize_key,
    get_db_connection,
    DB_FILE,
)
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_DB = "test_totally_not_my_privateKeys.db"


def make_test_key():
    # Generate a throwaway 2048-bit RSA key for testing
    return crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64_to_int(s):
    # Decode a Base64URL string to an integer
    padded = s + "=" * (-len(s) % 4)
    return int.from_bytes(b64.urlsafe_b64decode(padded), "big")


def start_test_server(port):
    # Start a real HTTPServer in a daemon thread on the given port
    server = HTTPServer(("localhost", port), MyServer)
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    return server


# ---------------------------------------------------------------------------
# Unit tests — int_to_base64
# ---------------------------------------------------------------------------

class TestIntToBase64(unittest.TestCase):

    # Should produce a URL-safe string with no padding
    def test_basic_value(self):
        result = int_to_base64(65537)
        self.assertIsInstance(result, str)
        self.assertNotIn("+", result)
        self.assertNotIn("/", result)
        self.assertNotIn("=", result)

    # Should round-trip correctly back to the original integer
    def test_roundtrip(self):
        value = 65537
        encoded = int_to_base64(value)
        decoded = b64_to_int(encoded)
        self.assertEqual(decoded, value)

    # Should pad a single hex digit (odd-length) correctly
    def test_odd_length_hex(self):
        result = int_to_base64(1)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)


# ---------------------------------------------------------------------------
# Unit tests — serialize_key / deserialize_key
# ---------------------------------------------------------------------------

class TestKeySerialization(unittest.TestCase):

    # Round-trip: serialise then deserialise should yield the same public key
    def test_roundtrip(self):
        key = make_test_key()
        pem = serialize_key(key)
        recovered = deserialize_key(pem)
        orig_pub = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        recv_pub = recovered.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(orig_pub, recv_pub)

    # serialize_key should return bytes starting with PEM header
    def test_serialize_returns_pem_bytes(self):
        key = make_test_key()
        pem = serialize_key(key)
        self.assertIsInstance(pem, bytes)
        self.assertIn(b"RSA PRIVATE KEY", pem)


# ---------------------------------------------------------------------------
# Unit tests — init_db and DB query helpers
# ---------------------------------------------------------------------------

class TestDatabase(unittest.TestCase):

    def setUp(self):
        # Redirect DB_FILE to a temp test DB for isolation
        self._patcher = patch("main.DB_FILE", TEST_DB)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

    # init_db should create the keys table and insert exactly 2 rows
    def test_init_db_creates_table_and_seeds(self):
        init_db()
        conn = sqlite3.connect(TEST_DB)
        count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)

    # init_db should always reset to exactly 2 rows even if called twice
    def test_init_db_resets_on_restart(self):
        init_db()
        init_db()
        conn = sqlite3.connect(TEST_DB)
        count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)

    # get_valid_key should return a key with future expiry
    def test_get_valid_key_returns_unexpired(self):
        init_db()
        pem, kid = get_valid_key()
        self.assertIsNotNone(pem)
        self.assertIsNotNone(kid)

    # get_expired_key should return a key with past expiry
    def test_get_expired_key_returns_expired(self):
        init_db()
        pem, kid = get_expired_key()
        self.assertIsNotNone(pem)
        self.assertIsNotNone(kid)

    # get_all_valid_keys should return only the one valid key
    def test_get_all_valid_keys_count(self):
        init_db()
        keys = get_all_valid_keys()
        self.assertEqual(len(keys), 1)

    # get_valid_key returns (None, None) when no valid key exists
    def test_get_valid_key_empty_db(self):
        # Create table but insert only an expired key
        conn = sqlite3.connect(TEST_DB)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS keys("
            "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
            "key BLOB NOT NULL,"
            "exp INTEGER NOT NULL)"
        )
        k = make_test_key()
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (serialize_key(k), int(time.time()) - 3600),
        )
        conn.commit()
        conn.close()
        pem, kid = get_valid_key()
        self.assertIsNone(pem)
        self.assertIsNone(kid)

    # get_expired_key returns (None, None) when no expired key exists
    def test_get_expired_key_empty_db(self):
        conn = sqlite3.connect(TEST_DB)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS keys("
            "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
            "key BLOB NOT NULL,"
            "exp INTEGER NOT NULL)"
        )
        k = make_test_key()
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (serialize_key(k), int(time.time()) + 3600),
        )
        conn.commit()
        conn.close()
        pem, kid = get_expired_key()
        self.assertIsNone(pem)
        self.assertIsNone(kid)


# ---------------------------------------------------------------------------
# Integration tests — live HTTP server
# ---------------------------------------------------------------------------

class TestHTTPEndpoints(unittest.TestCase):
    BASE = "http://localhost:8081"

    @classmethod
    def setUpClass(cls):
        # Point DB at test file, seed it, start server
        cls._db_patch = patch("main.DB_FILE", TEST_DB)
        cls._db_patch.start()
        init_db()
        cls._server = start_test_server(8081)
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._db_patch.stop()
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

    # GET /.well-known/jwks.json returns 200
    def test_jwks_200(self):
        r = requests.get(f"{self.BASE}/.well-known/jwks.json")
        self.assertEqual(r.status_code, 200)

    # JWKS response has correct Content-Type
    def test_jwks_content_type(self):
        r = requests.get(f"{self.BASE}/.well-known/jwks.json")
        self.assertIn("application/json", r.headers.get("Content-Type", ""))

    # JWKS response contains at least one key with all required fields
    def test_jwks_has_valid_key(self):
        r = requests.get(f"{self.BASE}/.well-known/jwks.json")
        data = r.json()
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0)
        for field in ("alg", "kty", "use", "kid", "n", "e"):
            self.assertIn(field, data["keys"][0])

    # Unknown GET path returns 405
    def test_jwks_unknown_path_405(self):
        r = requests.get(f"{self.BASE}/unknown")
        self.assertEqual(r.status_code, 405)

    # POST /auth returns 200
    def test_auth_200(self):
        r = requests.post(f"{self.BASE}/auth")
        self.assertEqual(r.status_code, 200)

    # POST /auth returns a JWT that verifies against the JWKS public key
    def test_auth_valid_jwt(self):
        r = requests.post(f"{self.BASE}/auth")
        token = r.text.strip()

        jwks = requests.get(f"{self.BASE}/.well-known/jwks.json").json()
        header = jwt.get_unverified_header(token)
        kid = header["kid"]
        jwk = next(k for k in jwks["keys"] if k["kid"] == kid)

        pub = RSAPublicNumbers(e=b64_to_int(jwk["e"]), n=b64_to_int(jwk["n"])).public_key()
        decoded = jwt.decode(token, pub, algorithms=["RS256"])
        self.assertIn("user", decoded)
        self.assertIn("exp", decoded)

    # POST /auth?expired returns 200
    def test_auth_expired_200(self):
        r = requests.post(f"{self.BASE}/auth?expired")
        self.assertEqual(r.status_code, 200)

    # JWT from ?expired has an exp claim in the past
    def test_auth_expired_jwt_is_expired(self):
        r = requests.post(f"{self.BASE}/auth?expired")
        token = r.text.strip()
        payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        self.assertLess(payload["exp"], int(time.time()))

    # POST to unknown path returns 405
    def test_auth_wrong_path_405(self):
        r = requests.post(f"{self.BASE}/other")
        self.assertEqual(r.status_code, 405)

    # Unsupported methods all return 405
    def test_put_405(self):
        self.assertEqual(requests.put(f"{self.BASE}/auth").status_code, 405)

    def test_patch_405(self):
        self.assertEqual(requests.patch(f"{self.BASE}/auth").status_code, 405)

    def test_delete_405(self):
        self.assertEqual(requests.delete(f"{self.BASE}/auth").status_code, 405)

    def test_head_405(self):
        self.assertEqual(requests.head(f"{self.BASE}/auth").status_code, 405)


# ---------------------------------------------------------------------------
# Edge case — no key in DB returns 500
# ---------------------------------------------------------------------------

class TestAuthNoKey(unittest.TestCase):
    BASE = "http://localhost:8082"

    @classmethod
    def setUpClass(cls):
        # Patch both query helpers to return nothing
        cls._valid_patch = patch("main.get_valid_key", return_value=(None, None))
        cls._expired_patch = patch("main.get_expired_key", return_value=(None, None))
        cls._valid_patch.start()
        cls._expired_patch.start()
        cls._server = start_test_server(8082)
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._valid_patch.stop()
        cls._expired_patch.stop()

    def test_no_valid_key_returns_500(self):
        r = requests.post(f"{self.BASE}/auth")
        self.assertEqual(r.status_code, 500)

    def test_no_expired_key_returns_500(self):
        r = requests.post(f"{self.BASE}/auth?expired")
        self.assertEqual(r.status_code, 500)


if __name__ == "__main__":
    unittest.main()

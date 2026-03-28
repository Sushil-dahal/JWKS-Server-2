# JWKS Server with SQLite - Project 2

A RESTful JWKS server that uses SQLite to store RSA private keys for JWT signing and verification.
This extends Project 1 by adding database persistence and SQL injection prevention.

## Author

sd1374

## Features

- SQLite database for persistent RSA private key storage
- Parameterized queries to prevent SQL injection
- JWT signing with RSA-256 keys
- Support for expired keys (for testing purposes)
- RESTful API endpoints with proper HTTP method enforcement

## Setup

Install dependencies:

```
pip install -r requirements.txt
```

## Running the Server

```
python3 main.py
```

Server runs on `http://localhost:8080`.

## API Endpoints

### GET `/.well-known/jwks.json`

Returns all valid (non-expired) public keys in JWKS format.

### POST `/auth`

Returns a signed JWT using a valid key. Accepts:
- HTTP Basic Auth
- JSON payload: `{"username": "userABC", "password": "password123"}`

### POST `/auth?expired`

Returns a JWT signed with an expired key for testing purposes.

All other HTTP methods (PUT, PATCH, DELETE, HEAD) return `405 Method Not Allowed`.

## Database

- File: `totally_not_my_privateKeys.db`
- Table: `keys` with columns `kid`, `key`, `exp`
- Keys are stored in PKCS1 PEM format
- One valid key (expires +1 hour) and one expired key (expired -1 hour) are seeded on every server start

## Testing

Run the test suite with coverage:

```
pytest test_main.py -v --cov=main --cov-report=term-missing
```

and
```
./gradebot project-2 --run="python3 main.py"
```


## Gradebot Results

Score: 65/85 on automated tests (Quality row pending network access on CSE machines)

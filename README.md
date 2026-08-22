# Auth Service

Authentication microservice for the **Realtime Order Processing System**. Handles user registration, login, and RS256 JWT access-token issuance.

Part of a distributed, event-driven architecture alongside Order, Inventory, and Payment services.

## Tech Stack

- Python 3.12+
- Django 6.x
- Django REST Framework 3.18
- PostgreSQL 16
- PyJWT + cryptography (RS256 access tokens)
- Structured JSON logging with correlation IDs

## Project Structure

```
auth_service/
├── config/                   # Django project settings
│   ├── settings.py
│   ├── test_settings.py      # SQLite in-memory for tests
│   └── urls.py
├── accounts/                 # User accounts app
│   ├── models.py             # Custom User model (AbstractUser + role)
│   ├── tests.py              # Unit + integration tests
│   ├── management/commands/
│   │   └── generate_rsa_keypair.py  # RSA key pair generation
│   └── api/
│       ├── urls.py
│       ├── views.py          # RegisterView, LoginView
│       └── serializers.py    # RegisterSerializer, LoginSerializer
├── accounts/services/
│   ├── keys.py               # RSA key pair generation logic
│   └── tokens.py             # Access-token issue / decode (RS256)
├── keys/                     # RSA keys (gitignored; see Setup step 3)
├── core/logging/             # Structured logging infrastructure
│   ├── config.py             # Logging configuration factory
│   ├── context.py            # contextvars-based tracing
│   ├── filters.py            # ContextFilter, HealthCheckFilter
│   ├── formatter.py          # JsonFormatter
│   └── middleware.py         # CorrelationMiddleware
├── docker-compose.yml        # PostgreSQL container
├── requirements.txt
└── Procfile
```

## Setup

### Prerequisites

- Python 3.12+
- PostgreSQL (or use Docker)

### 1. Start PostgreSQL

```bash
docker compose up -d
```

This starts PostgreSQL 16 on port `5436` with database `auth_db`.

### 2. Create virtual environment & install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Generate RSA keys

```bash
python manage.py generate_rsa_keypair
```

Writes `keys/private.pem` (mode 600, kept by this service) and `keys/public.pem` (copy to any service that needs to verify tokens). Use `--force` to overwrite.

### 4. Run migrations

```bash
python manage.py migrate
```

### 5. Start the server

```bash
python manage.py runserver 0.0.0.0:8003
```

The service runs on **port 8003**.

## API

Base URL: `http://localhost:8003`

Every response includes an `X-Correlation-ID` header. You can pass your own UUID in the request header; otherwise one is generated automatically.

### Login

```
POST /api/auth/login/
```

**Request Body:**

| Field      | Type   | Required |
|------------|--------|----------|
| `username` | string | Yes      |
| `password` | string | Yes      |

**Success Response (200):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "username": "johndoe",
    "role": "USER"
  }
}
```

#### curl

```bash
curl -X POST http://localhost:8003/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe", "password": "securepass123"}'
```

**Error Responses (401)** — wrong password, unknown username, or inactive account:

```json
{ "detail": "Invalid username or password." }
```

### Access Token Claims (RS256)

Signed with the service's RSA private key; verify with the public key.

| Claim        | Value                        | Notes                          |
|--------------|------------------------------|--------------------------------|
| `sub`        | `"6"`                        | User ID (string)               |
| `username`   | `"johndoe"`                  |                                |
| `role`       | `"USER"`                     | `USER` or `ADMIN`              |
| `token_type` | `"access"`                   |                                |
| `iss`        | `"auth-service"`             | Configurable via `JWT_ISSUER`  |
| `iat` / `exp`| Unix timestamps              | TTL: `ACCESS_TOKEN_TTL_SECONDS`|
| `jti`        | UUID                         | Unique token ID                |

Verifying in another service:

```python
import jwt

claims = jwt.decode(
    token,
    open("public.pem", "rb").read(),
    algorithms=["RS256"],
    issuer="auth-service",
)
```

### Register User

```
POST /api/auth/register/
```

**Request Body:**

| Field        | Type     | Required | Constraints              |
|--------------|----------|----------|--------------------------|
| `username`   | string   | Yes      | Must be unique           |
| `password`   | string   | Yes      | Minimum 8 characters     |
| `first_name` | string   | No       | Max 150 chars            |
| `last_name`  | string   | No       | Max 150 chars            |

**Success Response (201):**

```json
{
  "id": 1,
  "username": "newuser",
  "first_name": "John",
  "last_name": "Doe",
  "role": "USER"
}
```

#### curl

```bash
curl -X POST http://localhost:8003/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "securepass123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

Minimal (required fields only):

```bash
curl -X POST http://localhost:8003/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "janedoe",
    "password": "mypassword123"
  }'
```

With correlation ID:

```bash
curl -X POST http://localhost:8003/api/auth/register/ \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{
    "username": "bob",
    "password": "bobspassword123",
    "first_name": "Bob",
    "last_name": "Smith"
  }'
```

#### Error Responses (400)

Missing required field:

```bash
curl -X POST http://localhost:8003/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{"username": "onlyuser"}'
```

```json
{
  "password": ["This field is required."]
}
```

Password too short:

```bash
curl -X POST http://localhost:8003/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shortpw",
    "password": "123"
  }'
```

```json
{
  "password": ["Ensure this field has at least 8 characters."]
}
```

Duplicate username:

```bash
curl -X POST http://localhost:8003/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "anotherpass123"
  }'
```

```json
{
  "username": ["A user with that username already exists."]
}
```

## User Model

| Field        | Type            | Default  | Notes                              |
|--------------|-----------------|----------|------------------------------------|
| `id`         | BigAutoField    | auto     | Primary key                        |
| `username`   | CharField(150)  | --       | Unique                             |
| `password`   | CharField(128)  | --       | Stored as pbkdf2_sha256 hash       |
| `first_name` | CharField(150)  | `""`     | Optional                           |
| `last_name`  | CharField(150)  | `""`     | Optional                           |
| `email`      | EmailField      | `""`     | Optional                           |
| `role`       | CharField(10)   | `"USER"` | Choices: `USER`, `ADMIN`           |
| `is_active`  | BooleanField    | `True`   |                                    |
| `is_staff`   | BooleanField    | `False`  |                                    |
| `date_joined`| DateTimeField   | `now()`  |                                    |

Table name: `users`

## Environment Variables

| Variable                | Default                   | Purpose                          |
|-------------------------|---------------------------|----------------------------------|
| `SERVICE_NAME`          | `auth-service`            | Service identifier in logs       |
| `LOG_LEVEL`             | `INFO`                    | Root log level                   |
| `DB_LOG_LEVEL`          | `INFO`                    | Database query log level         |
| `LOG_FILE_PATH`         | `logs/application.log`    | Log file location                |
| `LOG_FILE_MAX_BYTES`    | `10485760` (10MB)         | Max log file size before rotation|
| `LOG_FILE_BACKUP_COUNT` | `3`                       | Number of rotated backups        |
| `JWT_PRIVATE_KEY_PATH`  | `keys/private.pem`        | RS256 signing key (secret)       |
| `JWT_PUBLIC_KEY_PATH`   | `keys/public.pem`         | Verification key                 |
| `JWT_ISSUER`            | `auth-service`            | Token issuer claim               |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` (15 min)         | Access-token lifetime            |

## Testing

```bash
python manage.py test
```

Tests use SQLite in-memory (`config/test_settings.py`) and cover:
- User model creation and password hashing
- Registration endpoint success cases
- Duplicate username validation
- Password length validation
- Missing required fields
- Login success / invalid credentials / inactive users
- RS256 signing, claim contents, expiry
- Signature tampering, HS256 algorithm-confusion, and wrong-key rejection

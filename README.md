# Spring Boot JWT Demo (Java 21)

A minimal, runnable Spring Boot 3 project that demonstrates JWT authentication end-to-end using HS256.

## Prerequisites
- Java 21
- Maven 3.9+

## Run
```bash
mvn spring-boot:run
```

The server starts on `http://localhost:8080`.

## Sample curl commands
Login (admin):
```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```

Public endpoint:
```bash
curl -s http://localhost:8080/api/public/ping
```

Call `/api/me` with an access token:
```bash
ACCESS_TOKEN=eyJ... 
curl -s http://localhost:8080/api/me \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

Call `/api/admin` (requires ADMIN role):
```bash
ACCESS_TOKEN=eyJ...
curl -s http://localhost:8080/api/admin \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

Refresh the access token (rotates refresh token):
```bash
REFRESH_TOKEN=eyJ...
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"'"${REFRESH_TOKEN}"'"}'
```

Logout (revokes refresh token jti only):
```bash
REFRESH_TOKEN=eyJ...
curl -s -X POST http://localhost:8080/api/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"'"${REFRESH_TOKEN}"'"}'
```

## JWT mental model
- **header.payload.signature**
  - The header and payload are Base64URL-encoded JSON, **not encrypted**. Never put secrets in the payload.
  - The signature proves integrity and authenticity with the shared secret (HS256 in this demo).
- **Stateless verification**
  - The server verifies the signature and claims on each request.
  - No session state is required for access tokens.
- **Gotchas & best practices**
  - **Signed ≠ encrypted**: Treat the payload as public.
  - **Validate claims**: `exp`, `iss`, `aud`, and `sub` are enforced in code.
  - **Short-lived access tokens + refresh tokens**: Access tokens are 5 minutes; refresh tokens are 7 days.
  - **Revocation**: Access tokens are stateless; this demo only revokes refresh tokens via a denylist.

## In-memory users
- `admin / admin123` with roles `USER`, `ADMIN`
- `user / user123` with role `USER`

## Configuration
Edit `src/main/resources/application.yml` to change the secret, issuer, audience, and token lifetimes.


# Spring Boot JWT Authentication

A minimal, production-ready Spring Boot 3 project demonstrating JWT authentication end-to-end using HS256, including access tokens, refresh token rotation, and role-based access control.

## Features
- 🔐 JWT-based authentication with HS256
- 🔄 Refresh token rotation for enhanced security
- 👥 Role-based access control (RBAC)
- 🚫 Token revocation with denylist
- ⏱️ Short-lived access tokens (5 minutes)
- 📝 Comprehensive validation of JWT claims
- 🛡️ Spring Security integration
- 📦 In-memory user store (easily adaptable to database)

## Prerequisites
- Java 21 or higher
- Maven 3.9+

## Quick Start
```bash
mvn spring-boot:run
```

The server starts on `http://localhost:8080`.

## API Endpoints

### Public Endpoints
- `GET /api/public/ping` - Health check endpoint

### Authentication Endpoints
- `POST /api/auth/login` - Login with username and password
- `POST /api/auth/refresh` - Refresh access token (rotates refresh token)
- `POST /api/auth/logout` - Revoke refresh token

### Protected Endpoints
- `GET /api/me` - Get current user info (requires authentication)
- `GET /api/admin` - Admin-only endpoint (requires ADMIN role)

## Sample curl commands
### 1. Login (admin):
```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1Q...",
  "refresh_token": "eyJ0eXAiOiJKV1Q...",
  "token_type": "Bearer",
  "expires_in_seconds": 299
}
```

### 2. Public endpoint:
```bash
curl -s http://localhost:8080/api/public/ping
```

### 3. Call `/api/me` with an access token:
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

### 4. Refresh the access token (rotates refresh token):
```bash
REFRESH_TOKEN=eyJ...
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"'"${REFRESH_TOKEN}"'"}'
```

### 5. Logout (revokes refresh token):
```bash
REFRESH_TOKEN=eyJ...
curl -s -X POST http://localhost:8080/api/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"'"${REFRESH_TOKEN}"'"}'
```

## Project Structure
```
src/main/java/com/example/jwt/
├── api/                    # REST controllers and DTOs
│   ├── ApiController.java
│   ├── AuthController.java
│   └── dto/
├── config/                 # Configuration classes
│   ├── JwtProperties.java
│   └── SecurityConfig.java
├── security/              # Security filters and handlers
│   ├── JwtAuthFilter.java
│   └── JwtUserPrincipal.java
└── service/               # Business logic
    ├── JwtService.java
    ├── TokenDenylistService.java
    └── UserService.java
```

## Technology Stack
- **Spring Boot 3.3.2**
- **Spring Security 6**
- **Nimbus JOSE + JWT** for JWT handling
- **Java 21**
- **Maven**

## Security Features
- ✅ JWT signature verification (HS256)
- ✅ Token expiration validation
- ✅ Issuer (`iss`) and audience (`aud`) validation
- ✅ Subject (`sub`) validation
- ✅ Clock skew tolerance (30 seconds)
- ✅ Refresh token rotation (old token invalidated on refresh)
- ✅ Token revocation via denylist
- ✅ Role-based access control
- ✅ CORS configuration
- ✅ Stateless authentication

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

## Configuration
Edit `src/main/resources/application.yml` to customize:
- JWT secret (minimum 32 bytes for HS256)
- Token lifetimes (access: 5 minutes, refresh: 7 days)
- Issuer and audience values
- CORS allowed origins

**⚠️ Important:** Change the JWT secret before deploying to production!

## In-memory Users
For demonstration purposes, two users are pre-configured:

| Username | Password   | Roles          |
|----------|------------|----------------|
| `admin`  | `admin123` | `USER`, `ADMIN`|
| `user`   | `user123`  | `USER`         |

## How It Works

### Authentication Flow
1. User logs in with credentials → receives access token + refresh token
2. Access token used for API requests (short-lived: 5 minutes)
3. When access token expires → use refresh token to get new tokens
4. Refresh token rotation: old refresh token invalidated, new one issued
5. Logout revokes the refresh token

### Token Structure
```
header.payload.signature
```
- **Header**: Algorithm (HS256) and token type (JWT)
- **Payload**: Claims (sub, iss, aud, exp, iat, jti, roles, token_type)
- **Signature**: HMAC-SHA256 signature for verification

**Note:** JWT payload is Base64URL-encoded, **not encrypted**. Never store sensitive data in claims.

## License
MIT License - feel free to use this project for learning or as a starting point for your applications.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.


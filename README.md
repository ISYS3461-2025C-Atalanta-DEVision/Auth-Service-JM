# Auth Service - User Manual

## Overview

Authentication microservice handling user login, registration, and JWT token management.

---

## API Endpoints for Frontend

Base URL: `https://auth-service-jm.onrender.com` (Production) or `http://localhost:8081` (Local)

### Registration

#### POST `/api/auth/register`
Register a new company account.

**Request Body:**
```json
{
    "email": "company@example.com",
    "password": "Password123!",
    "country": "Australia",
    "companyName": "My Company",
    "phoneNumber": "+61412345678",
    "streetAddress": "123 Main St",
    "city": "Melbourne"
}
```

**Validation Rules:**
- `email` (required): Valid email format, max 254 chars
- `password` (required): Min 8 chars, must include uppercase, lowercase, number, special character
- `country` (required): Must be from predefined list (use GET `/api/auth/countries`)
- `companyName` (optional): Max 255 chars
- `phoneNumber` (optional): International format with `+` prefix (e.g., `+61412345678`)
- `streetAddress` (optional): Max 255 chars
- `city` (optional): Max 100 chars

**Response (201 Created):**
```json
{
    "id": "uuid",
    "email": "company@example.com",
    "companyName": "My Company",
    "phoneNumber": "+61412345678",
    "streetAddress": "123 Main St",
    "city": "Melbourne",
    "country": "Australia",
    "status": "PENDING_ACTIVATION"
}
```

---

### Login

#### POST `/api/auth/login`
Authenticate user and get JWE tokens.

**Request Body:**
```json
{
    "email": "company@example.com",
    "password": "Password123!",
    "deviceInfo": "Chrome on Windows"
}
```

**Response (200 OK):**
```json
{
    "accessToken": "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "refreshExpiresIn": 604800,
    "user": {
        "id": "uuid",
        "email": "company@example.com",
        "role": "COMPANY",
        "companyName": "My Company",
        "country": "Australia"
    }
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account not activated or deactivated
- `423 Locked`: Account temporarily locked (brute-force protection)

---

### Token Refresh

#### POST `/api/auth/refresh`
Exchange refresh token for new access token.

**Request Body:**
```json
{
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK):**
```json
{
    "accessToken": "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0...",
    "refreshToken": "new-refresh-token-uuid",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "refreshExpiresIn": 604800
}
```

---

### Logout

#### POST `/api/auth/logout`
Revoke tokens and end session.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body (optional):**
```json
{
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK):** Empty body

---

### Account Activation

#### GET `/api/auth/activate/{token}`
Activate account via email link.

**Response (200 OK):** Empty body

---

### Password Reset

#### POST `/api/auth/forgot-password?email=user@example.com`
Request password reset email.

**Response (200 OK):** Empty body (always returns success to prevent email enumeration)

#### POST `/api/auth/reset-password/{token}?newPassword=NewPassword123!`
Reset password using token from email.

**Response (200 OK):** Empty body

---

### Change Password (Authenticated)

#### POST `/api/auth/change-password`
Change password for logged-in user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
    "currentPassword": "OldPassword123!",
    "newPassword": "NewPassword123!",
    "confirmPassword": "NewPassword123!"
}
```

**Response (200 OK):** Empty body

---

### Token Validation

#### GET `/api/auth/validate`
Validate access token (used by API Gateway).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
true
```

---

### Countries List

#### GET `/api/auth/countries`
Get list of valid countries for registration dropdown.

**Response (200 OK):**
```json
[
    "Afghanistan",
    "Albania",
    "Australia",
    ...
]
```

---

### Admin Login

#### POST `/api/auth/admin/login`
Admin authentication (same as regular login).

**Request Body:**
```json
{
    "email": "admin@example.com",
    "password": "AdminPassword123!"
}
```

---

### Google SSO

#### GET `/oauth2/authorization/google`
Redirect to Google login page.

After successful Google authentication, redirects to:
`{FRONTEND_URL}?token={accessToken}&refreshToken={refreshToken}`

---

## Error Response Format

All errors return:
```json
{
    "error": "ERROR_CODE",
    "message": "Human readable message",
    "path": "/api/auth/login",
    "timestamp": "2024-01-15T10:30:00"
}
```

**Common Error Codes:**
- `INVALID_CREDENTIALS`: Wrong email or password
- `ACCOUNT_NOT_ACTIVATED`: Email not verified
- `ACCOUNT_LOCKED`: Too many failed attempts
- `ACCOUNT_DEACTIVATED`: Account disabled
- `INVALID_TOKEN`: Token expired or invalid
- `EMAIL_ALREADY_EXISTS`: Email already registered

---

## Deploy to Render

1. Push `auth-service` folder to GitHub
2. Create **Web Service** on Render
3. Set environment variables:

| Key | Value |
|-----|-------|
| `PORT` | `8081` |
| `EUREKA_URL` | `https://eureka:password@eureka-server-cofs.onrender.com/eureka/` |
| `REDIS_HOST` | `your-redis-host` |
| `REDIS_PORT` | `6379` |
| `REDIS_PASSWORD` | `your-redis-password` |
| `REDIS_SSL_ENABLED` | `true` (for Upstash) |
| `JWT_SECRET` | `your-256-bit-secret` |
| `MONGODB_URI` | `mongodb+srv://user:pass@cluster.mongodb.net/dbname` |
| `INTERNAL_API_KEY` | `your-internal-api-key` |
| `SPRING_PROFILES_ACTIVE` | `prod` |
| `FRONTEND_URL` | `https://your-frontend.onrender.com` |
| `GOOGLE_CLIENT_ID` | `your-google-oauth-client-id` |
| `GOOGLE_CLIENT_SECRET` | `your-google-oauth-secret` |

---

## Run Locally

```bash
cd auth-service
mvn spring-boot:run
```

To connect to online Eureka:
```bash
EUREKA_URL=https://eureka:password@eureka-server-cofs.onrender.com/eureka/ mvn spring-boot:run
```

---

## Health Check

```bash
curl http://localhost:8081/actuator/health
```

---

## Using Access Token

Include the access token in all authenticated requests:

```
Authorization: Bearer eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0...
```

The token is a JWE (JSON Web Encryption) token - payload is encrypted and cannot be decoded without the server's key.

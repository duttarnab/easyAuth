# EasyAuth - OAuth 2.0 & OpenID Connect Server

A complete OAuth 2.0 and OpenID Connect (OIDC) server implementation built with Node.js, Express, TypeScript, and MongoDB. This server provides secure authentication and authorization services with support for multiple grant types, client management, and user management.

## Features

- ✅ **OAuth 2.0 Authorization Code Flow**
- ✅ **OpenID Connect (OIDC) Support**
- ✅ **JWT Access & Refresh Tokens**
- ✅ **Client Management**
- ✅ **User Management**
- ✅ **Token Revocation (RFC 7009)**
- ✅ **OIDC Logout**
- ✅ **JWKS Endpoint**
- ✅ **Rate Limiting & Security Headers**
- ✅ **Template-based Login/Logout UI**

## Quick Start

### Prerequisites

- Node.js 18+
- MongoDB
- npm or yarn

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd easyAuth/server

# Install dependencies
npm install

# Windows PowerShell users: if npm scripts are blocked by ExecutionPolicy
# either use cmd.exe (recommended)
#   cmd /c "npm run build"
# or temporarily bypass for this session:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Build the project
npm run build

# Start the server
npm start

# Or run in development mode
npm run dev
```

### Default Seed Data


- **Default client**: created on first start with generated `clientId`/`clientSecret`.
  - Redirect URIs: `http://localhost:3001/callback`, `http://localhost:3000/callback`
  - Grants: `authorization_code`, `refresh_token`
  - Scopes: `openid`, `profile`, `email`
  - Inspect values in your MongoDB `clients` collection.

### Environment Variables

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/oauth-server

# JWT Secrets
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# OAuth Configuration
ISSUER=http://localhost:3000
CLIENT_URL=http://localhost:3001
UI_BASE_URL=http://localhost:3001

# Session Configuration
SESSION_SECRET=your-session-secret
```

## API Documentation

### Base URL
```
http://localhost:3000
```

---

## 🔐 OAuth 2.0 & OIDC Endpoints

### 1. Authorization Endpoint

**Initiate Authorization**
```http
GET /oauth/authorize
```

**Parameters:**
- `client_id` (required): Client identifier
- `redirect_uri` (required): Redirect URI after authorization
- `response_type` (required): Must be "code"
- `scope` (required): Space-separated scopes (must include "openid")
- `state` (optional): CSRF protection parameter
- `nonce` (optional): OIDC nonce parameter
- `authorization_method` (optional): Authentication method ("basic", "sso", "magic_link")

**Example:**
```bash
curl "http://localhost:3000/oauth/authorize?client_id=my-client&redirect_uri=http://localhost:3001/callback&response_type=code&scope=openid profile email&state=xyz&authorization_method=basic"
```

**Response:**
- **302 Redirect** to login page (for basic auth) or client redirect URI with authorization code

---

### 2. Token Endpoint

**Exchange Authorization Code for Tokens**
```http
POST /oauth/token
Content-Type: application/json
Authorization: Basic base64(client_id:client_secret)  # or send in body
```

**Request Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code_here",
  "redirect_uri": "http://localhost:3001/callback",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

**Refresh Token**
```http
POST /oauth/token
Content-Type: application/json
Authorization: Basic base64(client_id:client_secret)  # optional if sent in body
```

**Request Body:**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "your_refresh_token",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret"
}
```

---

### 3. User Info Endpoint

**Get User Information**
```http
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "sub": "user_id",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true,
  "preferred_username": "john"
}
```

---

### 4. Introspection Endpoint (RFC 7662)

```http
POST /oauth/introspect
Content-Type: application/json
Authorization: Basic base64(client_id:client_secret)
```

**Request Body:**
```json
{
  "token": "<access_or_refresh_token>",
  "token_type_hint": "access_token"
}
```

**Response (active):**
```json
{
  "active": true,
  "client_id": "your_client_id",
  "exp": 1712345678,
  "iat": 1712342078,
  "sub": "user_id",
  "iss": "http://localhost:3000",
  "token_type": "access_token",
  "scope": "openid profile email",
  "auth_time": 1712342000
}
```

**Response (inactive):**
```json
{ "active": false }
```

---

### 5. Logout Endpoints

**Initiate Logout (OIDC)**
```http
GET /oauth/logout?post_logout_redirect_uri=https://client.com/logout&client_id=your_client_id&id_token_hint=your_id_token
```

**Confirm Logout**
```http
POST /oauth/logout
Content-Type: application/x-www-form-urlencoded

logout_token=logout_token_here
```

**Revoke Tokens (RFC 7009)**
```http
POST /oauth/revoke
Content-Type: application/json

{
  "token": "access_or_refresh_token",
  "token_type_hint": "access_token"
}
```

**End Session**
```http
GET /oauth/end-session?post_logout_redirect_uri=https://client.com/logout
```

---

### 6. OIDC Discovery & JWKS

**OpenID Connect Discovery**
```http
GET /oauth/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/oauth/authorize",
  "token_endpoint": "http://localhost:3000/oauth/token",
  "userinfo_endpoint": "http://localhost:3000/oauth/userinfo",
  "jwks_uri": "http://localhost:3000/oauth/jwks",
  "end_session_endpoint": "http://localhost:3000/oauth/logout",
  "revocation_endpoint": "http://localhost:3000/oauth/revoke",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "claims_supported": ["sub", "name", "given_name", "family_name", "email", "email_verified"]
}
```

**JSON Web Key Set (JWKS)**
```http
GET /oauth/jwks
```

---

## 👤 User Management API

### 1. User Registration

**Register New User**
```http
POST /api/users/register
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "name": "John Doe"
}
```

**Response:**
```json
{
  "id": "user_id",
  "email": "user@example.com",
  "name": "John Doe",
  "isVerified": false,
  "message": "User registered successfully. Please verify your email."
}
```

---

### 2. User Authentication

**Login**
```http
POST /oauth/login
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "session_token": "temporary_session_token",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "name": "John Doe",
    "isVerified": true
  }
}
```

**Verify Session**
```http
GET /oauth/verify-session
Authorization: Bearer <session_token>
```

---

### 3. User Profile Management

**Get User Profile**
```http
GET /api/users/profile
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "id": "user_id",
  "email": "user@example.com",
  "name": "John Doe",
  "isVerified": true,
  "createdAt": "2024-01-01T00:00:00.000Z"
}
```

**Update User Profile**
```http
PUT /api/users/profile
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "John Smith"
}
```

**Response:**
```json
{
  "id": "user_id",
  "email": "user@example.com",
  "name": "John Smith",
  "isVerified": true,
  "message": "Profile updated successfully"
}
```

---

## 🔧 Client Management API

### 1. Create OAuth Client

**Create New Client**
```http
POST /api/clients
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "My Application",
  "redirectUris": [
    "http://localhost:3001/callback",
    "https://myapp.com/callback"
  ],
  "grants": ["authorization_code", "refresh_token"],
  "scope": ["openid", "profile", "email"]
}
```

**Response:**
```json
{
  "clientId": "generated_client_id",
  "clientSecret": "generated_client_secret",
  "name": "My Application",
  "redirectUris": [
    "http://localhost:3001/callback",
    "https://myapp.com/callback"
  ],
  "grants": ["authorization_code", "refresh_token"],
  "scope": ["openid", "profile", "email"]
}
```

---

### 2. List User's Clients

**Get All Clients**
```http
GET /api/clients
Authorization: Bearer <access_token>
```

**Response:**
```json
[
  {
    "clientId": "client_id_1",
    "name": "My Application",
    "redirectUris": ["http://localhost:3001/callback"],
    "grants": ["authorization_code", "refresh_token"],
    "scope": ["openid", "profile", "email"],
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
]
```

---

### 3. Delete Client

**Delete Client**
```http
DELETE /api/clients/{clientId}
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Client deleted successfully"
}
```

---

## 🛡️ Security Features

### Rate Limiting
- **100 requests per 15 minutes** per IP address
- Applied to all endpoints

### Security Headers
- **Helmet.js** for security headers
- **CORS** configuration
- **Content Security Policy**

### Token Security
- **RS256** algorithm for ID tokens
- **HS256** for access tokens
- **Automatic token expiration**
- **Secure token storage**

### Password Security
- **bcrypt** hashing with 12 salt rounds
- **Minimum 6 character** password requirement

---

## 📋 Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "error_code",
  "error_description": "Human readable error description"
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `invalid_request` | Missing or invalid request parameters |
| `invalid_client` | Invalid client credentials |
| `invalid_grant` | Invalid or expired authorization code/refresh token |
| `invalid_scope` | Invalid or missing scope |
| `unauthorized_client` | Client not authorized for this grant type |
| `unsupported_grant_type` | Unsupported grant type |
| `server_error` | Internal server error |

---

## 🚀 Usage Examples

### Complete OAuth Flow Example

```bash
# 1. Register a user
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123","name":"John Doe"}'

# 2. Create a client
curl -X POST http://localhost:3000/api/clients \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","redirectUris":["http://localhost:3001/callback"],"grants":["authorization_code"],"scope":["openid","profile"]}'

# 3. Initiate authorization
curl "http://localhost:3000/oauth/authorize?client_id=<client_id>&redirect_uri=http://localhost:3001/callback&response_type=code&scope=openid profile&authorization_method=basic"

# 4. Exchange code for tokens
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<auth_code>","redirect_uri":"http://localhost:3001/callback","client_id":"<client_id>","client_secret":"<client_secret>"}'

# 5. Get user info
curl -X GET http://localhost:3000/oauth/userinfo \
  -H "Authorization: Bearer <access_token>"
```

---

## 🔧 Development

### Available Scripts

```bash
# Development
npm run dev          # Start development server with hot reload
npm run build        # Build TypeScript to JavaScript
npm start           # Start production server
npm test            # Run tests (when implemented)
```

### Project Structure

```
src/
├── controllers/     # Route handlers
├── middleware/      # Express middleware
├── models/          # Mongoose models
├── routes/          # Express routes
├── views/           # EJS templates
└── app.ts          # Express application setup
```

---

## 📝 License

ISC License

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📞 Support

For questions and support, please open an issue in the repository.
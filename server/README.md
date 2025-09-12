## Creating a Client

```
curl -X POST http://localhost:3000/api/clients \
  -H "Authorization: Bearer <user-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "redirectUris": ["http://localhost:3001/callback"],
    "grants": ["authorization_code", "refresh_token"],
    "scope": ["profile", "email"]
  }'
```

## Authorization Flow
1. Redirect user to: 
```
GET /oauth/authorize?client_id=<client_id>&redirect_uri=<redirect_uri>&response_type=code&scope=profile email
```
2. User authenticates and approves

3. Redirected to: `<redirect_uri>?code=<authorization_code>`

4. Exchange code for tokens: `POST /oauth/token` with `grant_type=authorization_code, code, redirect_uri, client_id, client_secret`

## Refresh Token

```
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "<refresh_token>",
    "client_id": "<client_id>",
    "client_secret": "<client_secret>"
  }'
```

This implementation provides a complete OAuth 2.0 server with authorization code flow, refresh tokens, client management, and proper security measures. Remember to add user registration and login endpoints as needed for your application.
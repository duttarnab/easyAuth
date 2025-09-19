# EasyAuth SCIM Service

SCIM 2.0 user provisioning API backed by EasyAuth's MongoDB users collection.

## Quick start

```bash
cd scim
npm install
npm run dev
```

Environment variables:

```
SCIM_PORT=3002
MONGODB_URI=mongodb://localhost:27017/oauth-server
CLIENT_URL=http://localhost:3001
```

## Endpoints

- Service Provider Config: `GET /scim/v2/ServiceProviderConfig`
- Users:
  - `GET /scim/v2/Users`
  - `POST /scim/v2/Users`
  - `GET /scim/v2/Users/{id}`
  - `PUT /scim/v2/Users/{id}`
  - `PATCH /scim/v2/Users/{id}`
  - `DELETE /scim/v2/Users/{id}`

Use a Bearer token in `Authorization` header. Wire your auth check in `requireBearer()`.

## Examples

```bash
curl -H "Authorization: Bearer test" http://localhost:3002/scim/v2/Users

curl -X POST -H "Authorization: Bearer test" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName":"jane@example.com",
    "name": {"formatted":"Jane Doe"},
    "active": true
  }' \
  http://localhost:3002/scim/v2/Users
```



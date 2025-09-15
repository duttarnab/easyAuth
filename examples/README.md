# easyAuth Examples

This folder contains a minimal example showing how to use the easyAuth server (port 3000) with:
- examples/backend: Express proxy (port 3002) to exchange authorization codes for tokens and expose a user API.
- examples/web-client: Vite + React app (port 3001) that initiates login and handles the callback.

Prerequisites:
- Node.js 18+
- easyAuth server running on http://localhost:3000
- A client registered with redirect URI http://localhost:3001/callback

Setup:
1) Start the server
```
cd server
npm install
npm run build
npm start
```
2) Start the backend proxy
```
cd ../examples/backend
npm install
cp .env.example .env
# Fill CLIENT_ID and CLIENT_SECRET in .env
npm start
```
3) Start the React app
```
cd ../web-client
npm install
npm run dev
```

Flow:
- React redirects to /oauth/authorize on the server
- Server redirects back to /callback with a code
- React posts the code to backend /auth/exchange
- Backend exchanges code for tokens and sets HTTP-only cookie
- React calls backend /api/me to get the profile

## Docker (examples)

Build and run combined examples image (backend + static web):
```
# From repo root
# Provide VITE_CLIENT_ID at build time for the web bundle
docker build -f examples/Dockerfile -t easyauth-examples --build-arg VITE_CLIENT_ID=your_client_id .

# Run and expose ports 3001 (web) and 3002 (backend)
docker run --rm -p 3001:3001 -p 3002:3002 \
  -e ISSUER=http://host.docker.internal:3000 \
  -e CLIENT_ID=your_client_id \
  -e CLIENT_SECRET=your_client_secret \
  -e REDIRECT_URI=http://localhost:3001/callback \
  easyauth-examples
```
Notes:
- On Mac/Windows, `host.docker.internal` lets the container reach the server at port 3000 on your host.
- On Linux, replace with your host IP or run the server in Docker and network them together.

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

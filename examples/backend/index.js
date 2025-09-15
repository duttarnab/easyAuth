import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002;
const ISSUER = process.env.ISSUER || 'http://localhost:3000';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3001/callback';
const COOKIE_NAME = process.env.COOKIE_NAME || 'access_token';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-cookie-secret';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3001';

app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(COOKIE_SECRET));

// Exchange authorization code for tokens
app.post('/auth/exchange', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'invalid_request', error_description: 'code is required' });

    const tokenRes = await fetch(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
      })
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.json().catch(() => ({}));
      return res.status(400).json(err);
    }

    const tokens = await tokenRes.json();

    // Store access token in HTTP-only cookie
    res.cookie(COOKIE_NAME, tokens.access_token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: tokens.expires_in ? tokens.expires_in * 1000 : 3600 * 1000
    });

    return res.json({ success: true, has_refresh_token: Boolean(tokens.refresh_token) });
  } catch (err) {
    console.error('exchange error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Get current user profile via /oauth/userinfo
app.get('/api/me', async (req, res) => {
  try {
    const accessToken = req.signedCookies?.[COOKIE_NAME] || req.cookies?.[COOKIE_NAME];
    if (!accessToken) return res.status(401).json({ error: 'invalid_token' });

    const meRes = await fetch(`${ISSUER}/oauth/userinfo`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!meRes.ok) {
      const err = await meRes.json().catch(() => ({}));
      return res.status(meRes.status).json(err);
    }

    const me = await meRes.json();
    return res.json(me);
  } catch (err) {
    console.error('me error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Clear cookie (logout client-side)
app.post('/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.status(204).end();
});

app.listen(PORT, () => {
  console.log(`Examples backend listening on http://localhost:${PORT}`);
});

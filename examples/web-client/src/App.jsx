import React, { useEffect, useState } from 'react';

const ISSUER = 'http://localhost:3000';
const BACKEND = 'http://localhost:3002';
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID || 'REPLACE_WITH_CLIENT_ID';
const REDIRECT_URI = 'http://localhost:3001/callback';
const SCOPE = 'openid profile email';

function buildAuthorizeUrl() {
  const url = new URL(`${ISSUER}/oauth/authorize`);
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', SCOPE);
  url.searchParams.set('state', Math.random().toString(36).slice(2));
  url.searchParams.set('authorization_method', 'basic');
  return url.toString();
}

export default function App() {
  const [me, setMe] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      if (code) {
        fetch(`${BACKEND}/auth/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ code })
        })
          .then(async (r) => {
            if (!r.ok) throw await r.json().catch(() => ({ error: 'exchange_failed' }));
            return r.json();
          })
          .then(() => {
            window.history.replaceState({}, '', '/');
            return fetch(`${BACKEND}/api/me`, { credentials: 'include' });
          })
          .then(async (r) => {
            if (!r.ok) throw await r.json().catch(() => ({ error: 'me_failed' }));
            return r.json();
          })
          .then(setMe)
          .catch(setError);
      }
    }
  }, []);

  const onLogin = () => {
    window.location.href = buildAuthorizeUrl();
  };

  const onFetchMe = () => {
    fetch(`${BACKEND}/api/me`, { credentials: 'include' })
      .then(async (r) => {
        if (!r.ok) throw await r.json().catch(() => ({ error: 'me_failed' }));
        return r.json();
      })
      .then(setMe)
      .catch(setError);
  };

  const onLogout = () => {
    fetch(`${BACKEND}/auth/logout`, { method: 'POST', credentials: 'include' })
      .then(() => setMe(null))
      .catch(() => setMe(null));
  };

  return (
    <div style={{ fontFamily: 'sans-serif', padding: 24 }}>
      <h1>easyAuth React Example</h1>
      <p>
        Server: {ISSUER} | Proxy: {BACKEND}
      </p>
      <p>
        Client ID: {CLIENT_ID === 'REPLACE_WITH_CLIENT_ID' ? 'not set (define VITE_CLIENT_ID)' : CLIENT_ID}
      </p>

      {!me ? (
        <>
          <button onClick={onLogin}>Login with easyAuth</button>
          <button onClick={onFetchMe} style={{ marginLeft: 8 }}>Fetch Profile</button>
        </>
      ) : (
        <>
          <pre>{JSON.stringify(me, null, 2)}</pre>
          <button onClick={onLogout}>Logout</button>
        </>
      )}

      {error && (
        <div style={{ color: 'red', marginTop: 16 }}>
          <pre>{JSON.stringify(error, null, 2)}</pre>
        </div>
      )}

      <hr />
      <p>
        Set VITE_CLIENT_ID in examples/web-client/.env (e.g., VITE_CLIENT_ID=your_client_id). Ensure redirect URI http://localhost:3001/callback is allowed.
      </p>
    </div>
  );
}

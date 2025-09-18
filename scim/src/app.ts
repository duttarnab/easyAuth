import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { usersRouter } from './routes/users';

dotenv.config();

const app = express();
const PORT = process.env.SCIM_PORT ? Number(process.env.SCIM_PORT) : 3002;

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL || '*', credentials: false }));
app.use(express.json({ type: ['application/json', 'application/scim+json'] }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(limiter);

app.get('/scim/v2/ServiceProviderConfig', (req, res) => {
  res.setHeader('Content-Type', 'application/scim+json');
  res.json({
    schemas: [
      'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
    ],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: true },
    etag: { supported: false },
    authenticationSchemes: [
      { type: 'oauthbearertoken', name: 'OAuth Bearer Token', description: 'Use Bearer token to authorize', primary: true }
    ]
  });
});

app.use('/scim/v2/Users', usersRouter);

app.get('/health', (_req, res) => {
  res.json({ status: 'OK', service: 'SCIM', timestamp: new Date().toISOString() });
});

function start() {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/oauth-server';
  mongoose.connect(mongoUri)
    .then(() => {
      console.log('SCIM connected to MongoDB');
      app.listen(PORT, () => {
        console.log(`SCIM service running on port ${PORT}`);
      });
    })
    .catch((err) => {
      console.error('SCIM MongoDB connection error:', err);
      process.exit(1);
    });
}

if (process.env.NODE_ENV !== 'test') {
  start();
}

export default app;



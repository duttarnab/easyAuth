import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import session from 'express-session';
import path from 'path';

import authRoutes from './routes/auth';
import clientRoutes from './routes/clients';
import userRoutes from './routes/users';
import { AuthController } from './controllers/authController';
import Client from './models/Client';
import User from './models/User';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize default data
async function initializeDefaultData() {
  try {
    // Create default user if none exists
    const existingUser = await User.findOne({ email: 'admin@example.com' });
    if (!existingUser) {
      const defaultUser = new User({
        email: 'admin@example.com',
        password: 'admin123',
        name: 'Admin User',
        isVerified: true,
        createdAt: new Date()
      });
      await defaultUser.save();
      console.log('Default user created!');
    } else {
      console.log('Default user already exists');
    }

    // Create default client if none exists
    const existingClient =  await Client.find({ clientId: { $exists: true } }); //await Client.findOne({ clientId: 'default-client' });
    if (!existingClient) {
      const defaultClient = new Client({
        //clientId: 'default-client',
        //clientSecret: 'default-secret',
        name: 'Default Client',
        redirectUris: ['http://localhost:3001/callback', 'http://localhost:3000/callback'],
        grants: ['authorization_code', 'refresh_token'],
        scope: ['openid', 'profile', 'email']
      });
      await defaultClient.save();
      console.log('Default client created!');
    } else {
      console.log('Default client already exists');
    }
  } catch (error) {
    console.error('Error initializing default data:', error);
  }
}

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3001',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware (for storing auth requests)
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 15 * 60 * 1000 // 15 minutes
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Routes
app.use('/oauth', authRoutes);
app.use('/api/clients', clientRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server_error', error_description: 'Something went wrong!' });
});

// Connect to MongoDB and initialize
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/oauth-server')
  .then(async () => {
    console.log('Connected to MongoDB');
    
    // Initialize default data
    await initializeDefaultData();
    
    // Initialize signing key if none exists
    try {
      await AuthController.getSigningKey();
      console.log('Signing key initialized');
    } catch (error) {
      console.error('Failed to initialize signing key:', error);
    }
    
    app.listen(PORT, () => {
      console.log(`OpenID Connect provider running on port ${PORT}`);
      console.log(`Discovery endpoint: http://localhost:${PORT}/oauth/.well-known/openid-configuration`);
    });
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });

export default app;
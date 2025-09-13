import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import * as jose from 'jose';
import Client from '../models/Client';
import User from '../models/User';
import Token from '../models/Token';
import { Types } from 'mongoose';
import AuthorizationCode from '../models/AuthorizationCode';
import Key from '../models/Key';

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh-secret';
const ISSUER = process.env.ISSUER || 'http://localhost:3000';

export class AuthController {
  // Generate RSA key pair for signing
  static async generateKeyPair() {
    try {
      const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
      
      const publicKeyJwk = await jose.exportJWK(publicKey);
      const privateKeyJwk = await jose.exportJWK(privateKey);
      
      const kid = uuidv4();
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
      
      const key = new Key({
        kid,
        publicKey: JSON.stringify(publicKeyJwk),
        privateKey: JSON.stringify(privateKeyJwk),
        algorithm: 'RS256',
        use: 'sig',
        expiresAt
      });
      
      await key.save();
      return key;
    } catch (error) {
      console.error('Key generation error:', error);
      throw error;
    }
  }

  // Get current signing key
  static async getSigningKey() {
    try {
      let key = await Key.findOne({ use: 'sig' }).sort({ createdAt: -1 });
      
      if (!key || new Date(key.expiresAt) < new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)) {
        // Generate new key if none exists or current one expires soon
        key = await AuthController.generateKeyPair();
      }
      
      return key;
    } catch (error) {
      console.error('Get signing key error:', error);
      throw error;
    }
  }

  // Authorization endpoint (updated for OIDC)
  static async authorize(req: Request, res: Response) {
  try {
    const { 
      client_id, 
      redirect_uri, 
      response_type, 
      scope, 
      state, 
      nonce,
      authorization_method = 'basic' // Default to 'basic'
    } = req.query;

    if (!client_id || !redirect_uri || !response_type) {
      return res.status(400).json({ 
        error: 'invalid_request', 
        error_description: 'Invalid request parameters' 
      });
    }

    if (response_type !== 'code') {
      return res.status(400).json({ 
        error: 'unsupported_response_type', 
        error_description: 'Unsupported response type' 
      });
    }

    // Check if openid scope is requested
    const scopes = scope ? (scope as string).split(' ') : [];
    if (!scopes.includes('openid')) {
      return res.status(400).json({ 
        error: 'invalid_scope', 
        error_description: 'openid scope is required' 
      });
    }

    const client = await Client.findOne({ clientId: client_id });
    if (!client) {
      return res.status(400).json({ 
        error: 'invalid_client', 
        error_description: 'Invalid client' 
      });
    }

    if (!client.redirectUris.includes(redirect_uri as string)) {
      return res.status(400).json({ 
        error: 'invalid_request', 
        error_description: 'Invalid redirect URI' 
      });
    }

    // Store authorization request in session or database
    const authRequestId = uuidv4();
    const authRequest = {
      id: authRequestId,
      client_id: client_id as string,
      redirect_uri: redirect_uri as string,
      response_type: response_type as string,
      scope: scopes,
      state: state as string,
      nonce: nonce as string,
      authorization_method: authorization_method as string,
      createdAt: new Date()
    };

    // In a real application, you'd store this in a database
    // For simplicity, we'll use a temporary storage
    (req as any).session = (req as any).session || {};
    (req as any).session.authRequests = (req as any).session.authRequests || {};
    (req as any).session.authRequests[authRequestId] = authRequest;

    // Handle different authorization methods
    switch (authorization_method) {
      case 'basic':
        // Redirect to login UI for username/password authentication
        // In a real app, you'd redirect to your login page
        const loginUrl = `${process.env.UI_BASE_URL || 'http://localhost:3001'}/login?auth_request_id=${authRequestId}`;
        return res.redirect(loginUrl);

      case 'sso':
        // Redirect to SSO provider
        // You would implement SSO integration here
        return res.status(501).json({ 
          error: 'not_implemented', 
          error_description: 'SSO authentication method not implemented' 
        });

      case 'magic_link':
        // Send magic link email
        return res.status(501).json({ 
          error: 'not_implemented', 
          error_description: 'Magic link authentication method not implemented' 
        });

      default:
        return res.status(400).json({ 
          error: 'invalid_request', 
          error_description: 'Unsupported authorization method' 
        });
    }

  } catch (error) {
    console.error('Authorization error:', error);
    return res.status(500).json({ 
      error: 'server_error', 
      error_description: 'Internal server error' 
    });
  }
}

// Add this method to handle authentication completion
static async completeAuthentication(req: Request, res: Response) {
  try {
    const { auth_request_id, user_id } = req.body;

    if (!auth_request_id || !user_id) {
      return res.status(400).json({ 
        error: 'invalid_request', 
        error_description: 'Auth request ID and user ID are required' 
      });
    }

    // Retrieve auth request from session
    const authRequest = (req as any).session?.authRequests?.[auth_request_id];
    if (!authRequest) {
      return res.status(400).json({ 
        error: 'invalid_request', 
        error_description: 'Invalid authentication request' 
      });
    }

    // Verify user exists
    const user = await User.findById(user_id);
    if (!user) {
      return res.status(400).json({ 
        error: 'invalid_request', 
        error_description: 'User not found' 
      });
    }

    // Generate authorization code
    const code = uuidv4();
    const authorizationCode = new AuthorizationCode({
      code,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      redirectUri: authRequest.redirect_uri,
      scope: authRequest.scope,
      client: await Client.findOne({ clientId: authRequest.client_id }),
      user: user_id,
      nonce: authRequest.nonce
    });

    await authorizationCode.save();

    // Clean up auth request
    delete (req as any).session.authRequests[auth_request_id];

    // Redirect back to client with authorization code
    const redirectUrl = new URL(authRequest.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (authRequest.state) redirectUrl.searchParams.set('state', authRequest.state);

    return res.json({ 
      redirect_uri: redirectUrl.toString(),
      code 
    });

  } catch (error) {
    console.error('Complete authentication error:', error);
    return res.status(500).json({ 
      error: 'server_error', 
      error_description: 'Internal server error' 
    });
  }
}

  // Token endpoint (updated for OIDC)
  static async token(req: Request, res: Response) {
    try {
      const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

      if (!grant_type) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid grant type' });
      }

      const client = await Client.findOne({ clientId: client_id });
      if (!client || client.clientSecret !== client_secret) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
      }

      if (grant_type === 'authorization_code') {
        if (!code || !redirect_uri) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid request' });
        }

        const authorizationCode = await AuthorizationCode.findOne({ code })
          .populate('client user');
        
        if (!authorizationCode || authorizationCode.expiresAt < new Date()) {
          return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });
        }

        if (authorizationCode.redirectUri !== redirect_uri) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect URI' });
        }

        // Generate tokens
        const accessToken = jwt.sign(
          { 
            sub: authorizationCode.user._id,
            client_id: client_id,
            scope: authorizationCode.scope,
            iss: ISSUER,
            aud: client_id
          },
          JWT_SECRET,
          { expiresIn: '1h' }
        );

        const refreshToken = jwt.sign(
          { 
            sub: authorizationCode.user._id,
            client_id: client_id
          },
          JWT_REFRESH_SECRET,
          { expiresIn: '7d' }
        );

        // Generate ID Token
        const signingKey = await AuthController.getSigningKey();
        const privateKey = await jose.importJWK(JSON.parse(signingKey.privateKey), 'RS256');
        
        const idToken = await new jose.SignJWT({
          sub: authorizationCode.user._id.toString()
          //name: authorizationCode.user.name,
          //email: authorizationCode.user.email,
          //email_verified: authorizationCode.user.isVerified
        })
          .setProtectedHeader({ alg: 'RS256', kid: signingKey.kid })
          .setIssuer(ISSUER)
          .setAudience(client_id)
          .setIssuedAt()
          .setExpirationTime('1h')
          .setSubject(authorizationCode.user._id.toString())
          .sign(privateKey);

        const accessTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        const refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        //const scopes = authorizationCode.scope.join(' ')
        
        // Save tokens
        const token = new Token({
          accessToken,
          accessTokenExpiresAt,
          refreshToken,
          refreshTokenExpiresAt,
          idToken,
          scope: authorizationCode.scope,
          client: client._id,
          user: authorizationCode.user._id
        });

        

        await token.save();
        await AuthorizationCode.deleteOne({ code });

        const response: any = {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: refreshToken,
          id_token: idToken,
          scope:  authorizationCode.scope?.join(' ')
        };

        return res.json(response);

      } else if (grant_type === 'refresh_token') {
        if (!refresh_token) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'Refresh token required' });
        }

        try {
          const decoded = jwt.verify(refresh_token, JWT_REFRESH_SECRET) as any;
          const existingToken = await Token.findOne({ refreshToken: refresh_token });

          if (!existingToken) {
            return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });
          }

          // Generate new access token
          const newAccessToken = jwt.sign(
            { 
              sub: decoded.sub,
              client_id: client_id,
              scope: existingToken.scope,
              iss: ISSUER,
              aud: client_id
            },
            JWT_SECRET,
            { expiresIn: '1h' }
          );

          // Generate new ID token if openid scope is present
          let newIdToken;
          if (existingToken.scope?.includes('openid')) {
            const user = await User.findById(decoded.sub);
            if (user) {
              const signingKey = await AuthController.getSigningKey();
              const privateKey = await jose.importJWK(JSON.parse(signingKey.privateKey), 'RS256');
              const userIdAsString: string = (user._id as Types.ObjectId).toString();

              newIdToken = await new jose.SignJWT({
                sub: userIdAsString,
                name: user.name,
                email: user.email,
                email_verified: user.isVerified
              })
                .setProtectedHeader({ alg: 'RS256', kid: signingKey.kid })
                .setIssuer(ISSUER)
                .setAudience(client_id)
                .setIssuedAt()
                .setExpirationTime('1h')
                .setSubject(userIdAsString)
                .sign(privateKey);
            }
          }

          const accessTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000);

          existingToken.accessToken = newAccessToken;
          existingToken.accessTokenExpiresAt = accessTokenExpiresAt;
          if (newIdToken) {
            existingToken.idToken = newIdToken;
          }
          await existingToken.save();

          const response: any = {
            access_token: newAccessToken,
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: refresh_token,
            scope: existingToken.scope?.join(' ')
          };

          if (newIdToken) {
            response.id_token = newIdToken;
          }

          return res.json(response);

        } catch (error) {
          return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });
        }
      } else {
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Unsupported grant type' });
      }
    } catch (error) {
      console.error('Token error:', error);
      return res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
    }
  }

  // User info endpoint (updated for OIDC)
  static async userInfo(req: Request, res: Response) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_token', error_description: 'Authorization header required' });
      }

      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, JWT_SECRET) as any;

      const user = await User.findById(decoded.sub).select('-password');
      if (!user) {
        return res.status(404).json({ error: 'invalid_token', error_description: 'User not found' });
      }
      const userIdAsString: string = (user._id as Types.ObjectId).toString();
      // Return standardized claims
      return res.json({
        sub: userIdAsString,
        name: user.name,
        given_name: user.name.split(' ')[0],
        family_name: user.name.split(' ').slice(1).join(' '),
        email: user.email,
        email_verified: user.isVerified,
        preferred_username: user.email.split('@')[0],
        //updated_at: Math.floor(user.updatedAt.getTime() / 1000)
      });
    } catch (error) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'Invalid token' });
    }
  }

  // JWKS endpoint
  static async jwks(req: Request, res: Response) {
    try {
      const keys = await Key.find({ use: 'sig' });
      
      const jwks = {
        keys: keys.map(key => {
          const publicKeyJwk = JSON.parse(key.publicKey);
          return {
            ...publicKeyJwk,
            kid: key.kid,
            use: 'sig',
            alg: 'RS256'
          };
        })
      };
      
      return res.json(jwks);
    } catch (error) {
      console.error('JWKS error:', error);
      return res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
    }
  }

  // OpenID Connect Discovery endpoint
  static async discovery(req: Request, res: Response) {
    try {
      const discovery = {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth/authorize`,
        token_endpoint: `${ISSUER}/oauth/token`,
        userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
        jwks_uri: `${ISSUER}/oauth/jwks`,
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
        claims_supported: ['sub', 'name', 'given_name', 'family_name', 'email', 'email_verified']
      };
      
      return res.json(discovery);
    } catch (error) {
      console.error('Discovery error:', error);
      return res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
    }
  }

  // Login endpoint
static async login(req: Request, res: Response) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        error: 'invalid_request', 
        error_description: 'Email and password are required' 
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        error: 'invalid_credentials', 
        error_description: 'Invalid email or password' 
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        error: 'invalid_credentials', 
        error_description: 'Invalid email or password' 
      });
    }

    // Generate temporary session token for UI authentication
    const sessionToken = jwt.sign(
      { 
        sub: user._id,
        email: user.email,
        name: user.name 
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({
      session_token: sessionToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ 
      error: 'server_error', 
      error_description: 'Internal server error' 
    });
  }
}

// Verify session token
static async verifySession(req: Request, res: Response) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'invalid_token', 
        error_description: 'Authorization header required' 
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    const user = await User.findById(decoded.sub).select('-password');
    if (!user) {
      return res.status(401).json({ 
        error: 'invalid_token', 
        error_description: 'User not found' 
      });
    }

    return res.json({
      valid: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    return res.status(401).json({ 
      error: 'invalid_token', 
      error_description: 'Invalid or expired token' 
    });
  }
}
}
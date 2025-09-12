"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const uuid_1 = require("uuid");
const Client_1 = __importDefault(require("../models/Client"));
const User_1 = __importDefault(require("../models/User"));
const Token_1 = __importDefault(require("../models/Token"));
const AuthorizationCode_1 = __importDefault(require("../models/AuthorizationCode"));
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh-secret';
class AuthController {
    // Authorization endpoint
    static async authorize(req, res) {
        try {
            const { client_id, redirect_uri, response_type, scope, state } = req.query;
            if (!client_id || !redirect_uri || !response_type) {
                return res.status(400).json({ error: 'Invalid request parameters' });
            }
            if (response_type !== 'code') {
                return res.status(400).json({ error: 'Unsupported response type' });
            }
            const client = await Client_1.default.findOne({ clientId: client_id });
            if (!client) {
                return res.status(400).json({ error: 'Invalid client' });
            }
            if (!client.redirectUris.includes(redirect_uri)) {
                return res.status(400).json({ error: 'Invalid redirect URI' });
            }
            // In a real application, you'd show a consent screen here
            // For simplicity, we'll assume the user is already authenticated
            const userId = req.user?.id; // Assuming user is authenticated via middleware
            if (!userId) {
                return res.status(401).json({ error: 'User not authenticated' });
            }
            const code = (0, uuid_1.v4)();
            const authorizationCode = new AuthorizationCode_1.default({
                code,
                expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
                redirectUri: redirect_uri,
                scope: scope ? scope.split(' ') : [],
                client: client._id,
                user: userId
            });
            await authorizationCode.save();
            const redirectUrl = new URL(redirect_uri);
            redirectUrl.searchParams.set('code', code);
            if (state)
                redirectUrl.searchParams.set('state', state);
            return res.redirect(redirectUrl.toString());
        }
        catch (error) {
            console.error('Authorization error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
    // Token endpoint
    static async token(req, res) {
        try {
            const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;
            if (!grant_type) {
                return res.status(400).json({ error: 'Invalid grant type' });
            }
            const client = await Client_1.default.findOne({ clientId: client_id });
            if (!client || client.clientSecret !== client_secret) {
                return res.status(401).json({ error: 'Invalid client credentials' });
            }
            if (grant_type === 'authorization_code') {
                if (!code || !redirect_uri) {
                    return res.status(400).json({ error: 'Invalid request' });
                }
                const authorizationCode = await AuthorizationCode_1.default.findOne({ code })
                    .populate('client user');
                if (!authorizationCode || authorizationCode.expiresAt < new Date()) {
                    return res.status(400).json({ error: 'Invalid or expired authorization code' });
                }
                if (authorizationCode.redirectUri !== redirect_uri) {
                    return res.status(400).json({ error: 'Invalid redirect URI' });
                }
                // Generate tokens
                const accessToken = jsonwebtoken_1.default.sign({
                    userId: authorizationCode.user._id,
                    clientId: client_id,
                    scope: authorizationCode.scope
                }, JWT_SECRET, { expiresIn: '1h' });
                const refreshToken = jsonwebtoken_1.default.sign({
                    userId: authorizationCode.user._id,
                    clientId: client_id
                }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
                const accessTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
                const refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
                // Save tokens
                const token = new Token_1.default({
                    accessToken,
                    accessTokenExpiresAt,
                    refreshToken,
                    refreshTokenExpiresAt,
                    scope: authorizationCode.scope,
                    client: client._id,
                    user: authorizationCode.user._id
                });
                await token.save();
                await AuthorizationCode_1.default.deleteOne({ code });
                return res.json({
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    refresh_token: refreshToken,
                    scope: authorizationCode.scope?.join(' ') || ''
                });
            }
            else if (grant_type === 'refresh_token') {
                if (!refresh_token) {
                    return res.status(400).json({ error: 'Refresh token required' });
                }
                try {
                    const decoded = jsonwebtoken_1.default.verify(refresh_token, JWT_REFRESH_SECRET);
                    const existingToken = await Token_1.default.findOne({ refreshToken: refresh_token });
                    if (!existingToken) {
                        return res.status(401).json({ error: 'Invalid refresh token' });
                    }
                    // Generate new access token
                    const newAccessToken = jsonwebtoken_1.default.sign({
                        userId: decoded.userId,
                        clientId: client_id,
                        scope: existingToken.scope
                    }, JWT_SECRET, { expiresIn: '1h' });
                    const accessTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000);
                    existingToken.accessToken = newAccessToken;
                    existingToken.accessTokenExpiresAt = accessTokenExpiresAt;
                    await existingToken.save();
                    return res.json({
                        access_token: newAccessToken,
                        token_type: 'Bearer',
                        expires_in: 3600,
                        refresh_token: refresh_token,
                        scope: existingToken.scope?.join(' ')
                    });
                }
                catch (error) {
                    return res.status(401).json({ error: 'Invalid refresh token' });
                }
            }
            else {
                return res.status(400).json({ error: 'Unsupported grant type' });
            }
        }
        catch (error) {
            console.error('Token error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
    // User info endpoint
    static async userInfo(req, res) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Authorization header required' });
            }
            const token = authHeader.substring(7);
            const decoded = jsonwebtoken_1.default.verify(token, JWT_SECRET);
            const user = await User_1.default.findById(decoded.userId).select('-password');
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            return res.json({
                sub: user._id,
                name: user.name,
                email: user.email,
                email_verified: user.isVerified
            });
        }
        catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    }
}
exports.AuthController = AuthController;
//# sourceMappingURL=authController.js.map
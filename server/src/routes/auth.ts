import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { authenticateToken, optionalAuth } from '../middleware/auth';

const router = Router();

// OAuth endpoints
router.get('/authorize', optionalAuth, AuthController.authorize);
router.post('/token', AuthController.token);
router.get('/userinfo', authenticateToken, AuthController.userInfo);

// OIDC endpoints
router.get('/.well-known/openid-configuration', AuthController.discovery);
router.get('/jwks', AuthController.jwks);

// Authentication endpoints
router.post('/login', AuthController.login);
router.post('/login-form', AuthController.loginForm);
router.get('/verify-session', AuthController.verifySession);
router.post('/complete-auth', AuthController.completeAuthentication);

// Logout endpoints
router.get('/logout', AuthController.initiateLogout);
router.post('/logout', AuthController.confirmLogout);
router.post('/revoke', AuthController.revokeTokens);
router.get('/end-session', AuthController.endSession);

export default router;
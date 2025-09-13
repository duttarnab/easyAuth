import { Router } from 'express';
import { AuthController } from '../controllers/authController';

const router = Router();

// OpenID Connect Discovery endpoint
router.get('/.well-known/openid-configuration', AuthController.discovery);

// JWKS endpoint
router.get('/jwks', AuthController.jwks);

export default router;
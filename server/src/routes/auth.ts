import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { authenticateToken, optionalAuth } from '../middleware/auth';

const router = Router();

router.get('/authorize', optionalAuth, AuthController.authorize);
router.post('/token', AuthController.token);
router.get('/userinfo', authenticateToken, AuthController.userInfo);

export default router;
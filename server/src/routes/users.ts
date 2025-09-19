import { Router } from 'express';
import { UserController } from '../controllers/userController';
import { authenticateToken } from '../middleware/auth';

const router = Router();

// Public routes
//router.post('/register', UserController.register);

// Protected routes
router.get('/profile', authenticateToken, UserController.getProfile);
//router.put('/profile', authenticateToken, UserController.updateProfile);

export default router;
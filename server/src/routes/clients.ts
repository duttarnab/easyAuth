import { Router } from 'express';
import { ClientController } from '../controllers/clientController';
import { authenticateToken } from '../middleware/auth';

const router = Router();

router.post('/', authenticateToken, ClientController.createClient);
router.get('/', authenticateToken, ClientController.getClients);
router.delete('/:clientId', authenticateToken, ClientController.deleteClient);

export default router;
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const clientController_1 = require("../controllers/clientController");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.post('/', auth_1.authenticateToken, clientController_1.ClientController.createClient);
router.get('/', auth_1.authenticateToken, clientController_1.ClientController.getClients);
router.delete('/:clientId', auth_1.authenticateToken, clientController_1.ClientController.deleteClient);
exports.default = router;
//# sourceMappingURL=clients.js.map
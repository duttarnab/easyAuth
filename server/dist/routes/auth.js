"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const authController_1 = require("../controllers/authController");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.get('/authorize', auth_1.optionalAuth, authController_1.AuthController.authorize);
router.post('/token', authController_1.AuthController.token);
router.get('/userinfo', auth_1.authenticateToken, authController_1.AuthController.userInfo);
exports.default = router;
//# sourceMappingURL=auth.js.map
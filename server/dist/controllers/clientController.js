"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClientController = void 0;
const Client_1 = __importDefault(require("../models/Client"));
class ClientController {
    static async createClient(req, res) {
        try {
            const { name, redirectUris, grants, scope } = req.body;
            const userId = req.user.id;
            const client = new Client_1.default({
                name,
                redirectUris,
                grants: grants || ['authorization_code', 'refresh_token'],
                scope: scope || [],
                user: userId
            });
            await client.save();
            return res.status(201).json({
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                name: client.name,
                redirectUris: client.redirectUris,
                grants: client.grants,
                scope: client.scope
            });
        }
        catch (error) {
            console.error('Create client error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
    static async getClients(req, res) {
        try {
            const userId = req.user.id;
            const clients = await Client_1.default.find({ user: userId }).select('-clientSecret');
            return res.json(clients);
        }
        catch (error) {
            console.error('Get clients error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
    static async deleteClient(req, res) {
        try {
            const { clientId } = req.params;
            const userId = req.user.id;
            const client = await Client_1.default.findOne({ clientId, user: userId });
            if (!client) {
                return res.status(404).json({ error: 'Client not found' });
            }
            await Client_1.default.deleteOne({ clientId });
            return res.json({ message: 'Client deleted successfully' });
        }
        catch (error) {
            console.error('Delete client error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
}
exports.ClientController = ClientController;
//# sourceMappingURL=clientController.js.map
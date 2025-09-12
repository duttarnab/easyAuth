import { Request, Response } from 'express';
import Client from '../models/Client';

export class ClientController {
  static async createClient(req: Request, res: Response) {
    try {
      const { name, redirectUris, grants, scope } = req.body;
      const userId = (req as any).user.id;

      const client = new Client({
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
    } catch (error) {
      console.error('Create client error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async getClients(req: Request, res: Response) {
    try {
      const userId = (req as any).user.id;
      const clients = await Client.find({ user: userId }).select('-clientSecret');

      return res.json(clients);
    } catch (error) {
      console.error('Get clients error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  static async deleteClient(req: Request, res: Response) {
    try {
      const { clientId } = req.params;
      const userId = (req as any).user.id;

      const client = await Client.findOne({ clientId, user: userId });
      if (!client) {
        return res.status(404).json({ error: 'Client not found' });
      }

      await Client.deleteOne({ clientId });
      return res.json({ message: 'Client deleted successfully' });
    } catch (error) {
      console.error('Delete client error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
}
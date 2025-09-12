import { Request, Response } from 'express';
export declare class ClientController {
    static createClient(req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
    static getClients(req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
    static deleteClient(req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
}
//# sourceMappingURL=clientController.d.ts.map
import { Request, Response } from 'express';
export declare class AuthController {
    static authorize(req: Request, res: Response): Promise<void | Response<any, Record<string, any>>>;
    static token(req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
    static userInfo(req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
}
//# sourceMappingURL=authController.d.ts.map
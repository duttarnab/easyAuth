import mongoose, { Document } from 'mongoose';
export interface IAuthorizationCode extends Document {
    code: string;
    expiresAt: Date;
    redirectUri: string;
    scope?: string[];
    client: mongoose.Types.ObjectId;
    user: mongoose.Types.ObjectId;
    createdAt: Date;
}
declare const _default: mongoose.Model<IAuthorizationCode, {}, {}, {}, mongoose.Document<unknown, {}, IAuthorizationCode, {}, {}> & IAuthorizationCode & Required<{
    _id: unknown;
}> & {
    __v: number;
}, any>;
export default _default;
//# sourceMappingURL=AuthorizationCode.d.ts.map
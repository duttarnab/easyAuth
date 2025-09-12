import mongoose, { Document } from 'mongoose';
export interface IToken extends Document {
    accessToken: string;
    accessTokenExpiresAt: Date;
    refreshToken: string;
    refreshTokenExpiresAt: Date;
    scope?: string[];
    client: mongoose.Types.ObjectId;
    user: mongoose.Types.ObjectId;
    createdAt: Date;
}
declare const _default: mongoose.Model<IToken, {}, {}, {}, mongoose.Document<unknown, {}, IToken, {}, {}> & IToken & Required<{
    _id: unknown;
}> & {
    __v: number;
}, any>;
export default _default;
//# sourceMappingURL=Token.d.ts.map
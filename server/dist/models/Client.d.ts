import mongoose, { Document } from 'mongoose';
export interface IClient extends Document {
    clientId: string;
    clientSecret: string;
    name: string;
    redirectUris: string[];
    grants: string[];
    scope?: string[];
    user: mongoose.Types.ObjectId;
    createdAt: Date;
    updatedAt: Date;
}
declare const _default: mongoose.Model<IClient, {}, {}, {}, mongoose.Document<unknown, {}, IClient, {}, {}> & IClient & Required<{
    _id: unknown;
}> & {
    __v: number;
}, any>;
export default _default;
//# sourceMappingURL=Client.d.ts.map
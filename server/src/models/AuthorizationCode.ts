import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IAuthorizationCode extends Document {
  code: string;
  expiresAt: Date;
  redirectUri: string;
  scope?: string[];
  // During queries we often populate these refs; reflect that in types
  client: Types.ObjectId | { clientId: string };
  user: Types.ObjectId | { _id: Types.ObjectId };
  // OIDC additions
  nonce?: string;
  authTime?: Date;
  createdAt: Date;
}

const AuthorizationCodeSchema: Schema = new Schema({
  code: {
    type: String,
    required: true,
    unique: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  redirectUri: {
    type: String,
    required: true
  },
  scope: [{
    type: String
  }],
  client: {
    type: Schema.Types.ObjectId,
    ref: 'Client',
    required: true
  },
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  nonce: {
    type: String
  },
  authTime: {
    type: Date
  }
}, {
  timestamps: true
});

AuthorizationCodeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IAuthorizationCode>('AuthorizationCode', AuthorizationCodeSchema);
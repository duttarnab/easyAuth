import mongoose, { Document, Schema } from 'mongoose';

export interface IAuthorizationCode extends Document {
  code: string;
  expiresAt: Date;
  redirectUri: string;
  scope?: string[];
  client: mongoose.Types.ObjectId;
  user: mongoose.Types.ObjectId;
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
  }
}, {
  timestamps: true
});

AuthorizationCodeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IAuthorizationCode>('AuthorizationCode', AuthorizationCodeSchema);
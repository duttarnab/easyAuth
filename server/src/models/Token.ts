import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IToken extends Document {
  accessToken: string;
  accessTokenExpiresAt: Date;
  refreshToken?: string;
  refreshTokenExpiresAt?: Date;
  idToken: string; // Required for OIDC
  scope?: string[];
  // During queries we often populate these refs; reflect that in types
  client: Types.ObjectId | { clientId: string; _id?: Types.ObjectId };
  user: Types.ObjectId | { _id: Types.ObjectId };
  nonce?: string; // Required for OIDC id_token validation
  authTime: Date; // Time of authentication
  acr?: string; // Authentication Context Class Reference
  amr?: string[]; // Authentication Methods References
  createdAt: Date;
}

const TokenSchema: Schema = new Schema({
  accessToken: {
    type: String,
    required: true,
    unique: true
  },
  accessTokenExpiresAt: {
    type: Date,
    required: true
  },
  refreshToken: {
    type: String,
    unique: true,
    sparse: true // Allows null values but enforces uniqueness for non-null
  },
  refreshTokenExpiresAt: {
    type: Date
  },
  idToken: {
    type: String,
    required: true,
    unique: true
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
    type: Date,
    required: true,
    default: Date.now
  },
  acr: {
    type: String
  },
  amr: [{
    type: String
  }]
}, {
  timestamps: true
});

TokenSchema.index({ accessTokenExpiresAt: 1 }, { expireAfterSeconds: 0 });
TokenSchema.index({ refreshTokenExpiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IToken>('Token', TokenSchema);
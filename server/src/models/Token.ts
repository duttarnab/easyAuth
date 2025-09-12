import mongoose, { Document, Schema } from 'mongoose';

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
    required: true,
    unique: true
  },
  refreshTokenExpiresAt: {
    type: Date,
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

TokenSchema.index({ accessTokenExpiresAt: 1 }, { expireAfterSeconds: 0 });
TokenSchema.index({ refreshTokenExpiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IToken>('Token', TokenSchema);
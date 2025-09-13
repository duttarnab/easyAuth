import mongoose, { Document, Schema } from 'mongoose';

export interface IKey extends Document {
  kid: string;
  publicKey: string;
  privateKey: string;
  algorithm: string;
  use: string;
  createdAt: Date;
  expiresAt: Date;
}

const KeySchema: Schema = new Schema({
  kid: {
    type: String,
    required: true,
    unique: true
  },
  publicKey: {
    type: String,
    required: true
  },
  privateKey: {
    type: String,
    required: true
  },
  algorithm: {
    type: String,
    required: true,
    default: 'RS256'
  },
  use: {
    type: String,
    required: true,
    enum: ['sig', 'enc'],
    default: 'sig'
  },
  expiresAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

KeySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IKey>('Key', KeySchema);
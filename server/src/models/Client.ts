import mongoose, { Document, Schema } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

export interface IClient extends Document {
  clientId: string;
  clientSecret: string;
  name: string;
  redirectUris: string[];
  grants: string[];
  scope?: string[];
  user?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const ClientSchema: Schema = new Schema({
  clientId: {
    type: String,
    required: true,
    unique: true,
    default: uuidv4
  },
  clientSecret: {
    type: String,
    required: true,
    default: uuidv4
  },
  name: {
    type: String,
    required: true
  },
  redirectUris: [{
    type: String,
    required: true
  }],
  grants: [{
    type: String,
    enum: ['authorization_code', 'password', 'client_credentials', 'refresh_token'],
    required: true
  }],
  scope: [{
    type: String
  }],
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: false
  }
}, {
  timestamps: true
});

export default mongoose.model<IClient>('Client', ClientSchema);
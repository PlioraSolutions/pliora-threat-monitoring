import mongoose, { Schema, Document, Model, Types } from 'mongoose';
import { UserRole, GlobalRole } from '@/types';

export interface IOrganizationMembership {
  organizationId: Types.ObjectId;
  role: UserRole;
  joinedAt: Date;
}

export interface IUser extends Document {
  email: string;
  passwordHash: string;
  name: string;
  globalRole: GlobalRole;
  organizationMemberships: IOrganizationMembership[];
  activeOrganizationId: Types.ObjectId;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    passwordHash: { type: String, required: true },
    name: { type: String, required: true, trim: true },
    globalRole: {
      type: String,
      enum: ['SUPERADMIN', 'USER'],
      default: 'USER',
    },
    organizationMemberships: [
      {
        organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true },
        role: {
          type: String,
          enum: ['OWNER', 'ADMIN', 'MEMBER', 'VIEWER'],
          default: 'MEMBER',
        },
        joinedAt: { type: Date, default: Date.now },
      },
    ],
    activeOrganizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true },
    lastLoginAt: { type: Date },
  },
  { timestamps: true }
);

export const User: Model<IUser> =
  mongoose.models.User || mongoose.model<IUser>('User', UserSchema);

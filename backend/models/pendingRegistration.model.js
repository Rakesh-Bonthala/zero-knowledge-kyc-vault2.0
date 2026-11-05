import mongoose from 'mongoose';

const pendingRegistrationSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 30
    },
    usernameNormalized: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true
    },
    email: {
      type: String,
      required: true,
      trim: true,
      maxlength: 254
    },
    emailNormalized: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true
    },
    passwordHash: {
      type: String,
      required: true
    },
    termsAcceptedAt: {
      type: Date,
      required: true
    },
    termsVersion: {
      type: String,
      default: 'v1.0'
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 } // MongoDB TTL index auto-deletes expired records
    }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

export const PendingRegistrationModel =
  mongoose.models.PendingRegistration ||
  mongoose.model('PendingRegistration', pendingRegistrationSchema);


import mongoose from 'mongoose';

const otpChallengeSchema = new mongoose.Schema(
  {
    targetId: {
      type: String,
      required: true,
      index: true
    },
    targetType: {
      type: String,
      enum: ['pending_registration', 'user'],
      required: true
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true
    },
    purpose: {
      type: String,
      enum: ['register', 'login', 'reset'],
      required: true,
      index: true
    },
    otpHmac: {
      type: String,
      required: true
    },
    attempts: {
      type: Number,
      default: 0
    },
    used: {
      type: Boolean,
      default: false,
      index: true
    },
    lastSentAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 } // MongoDB TTL index auto-deletes expired records
    }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

// Compound index for lookup by target and purpose
otpChallengeSchema.index({ targetId: 1, purpose: 1, used: 1 });
otpChallengeSchema.index({ email: 1, purpose: 1, used: 1 });

export const OtpChallengeModel =
  mongoose.models.OtpChallenge || mongoose.model('OtpChallenge', otpChallengeSchema);


import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
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
      unique: true,
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
      unique: true,
      trim: true,
      lowercase: true,
      index: true
    },
    passwordHash: {
      type: String,
      required: true
    },
    isEmailVerified: {
      type: Boolean,
      default: true // Created only after email OTP verification
    },
    accountStatus: {
      type: String,
      enum: ['active', 'locked', 'disabled'],
      default: 'active',
      index: true
    },
    termsAcceptedAt: {
      type: Date,
      required: true
    },
    termsVersion: {
      type: String,
      default: 'v1.0'
    },
    failedLoginCount: {
      type: Number,
      default: 0
    },
    lockedUntil: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

export const UserModel = mongoose.models.User || mongoose.model('User', userSchema);


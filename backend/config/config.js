import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

// Ephemeral dev secrets fallback if not specified in environment
const defaultDevSecret = crypto.randomBytes(32).toString('hex');

export const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  storageProvider: (process.env.STORAGE_PROVIDER || 'gridfs').toLowerCase(),
  allowMockFallback: process.env.STORAGE_ALLOW_MOCK_FALLBACK !== 'false',
  maxFileSizeMB: parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 50,
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',

  // Authentication & Session Security
  auth: {
    sessionSecret: process.env.SESSION_SECRET || defaultDevSecret,
    otpSecret: process.env.OTP_SECRET || defaultDevSecret,
    csrfSecret: process.env.CSRF_SECRET || defaultDevSecret,
    sessionName: 'zk_vault_sid',
    sessionMaxAgeMs: 24 * 60 * 60 * 1000, // 24 hours absolute
    idleTimeoutMs: 30 * 60 * 1000,         // 30 minutes idle
    otpExpiryMinutes: 5,
    pendingRegistrationExpiryMinutes: 15,
    maxOtpAttempts: 5,
    resendCooldownSeconds: 60,
    maxResendsPerHour: 5,
    accountLockoutThreshold: 5,
    accountLockoutDurationMinutes: 15
  },

  // Email Notification Transport
  email: {
    smtpHost: process.env.SMTP_HOST || '',
    smtpPort: parseInt(process.env.SMTP_PORT, 10) || 587,
    smtpUser: process.env.SMTP_USER || '',
    smtpPass: process.env.SMTP_PASS || '',
    fromAddress: process.env.EMAIL_FROM || 'no-reply@zeroknowledgevault.com'
  },

  // MongoDB GridFS
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/zk_kyc_vault',
    bucketName: 'encrypted_documents',
    options: {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    }
  },

  // AWS S3
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
    bucket: process.env.AWS_S3_BUCKET || 'zk-kyc-vault-bucket'
  },

  // Firebase
  firebase: {
    projectId: process.env.FIREBASE_PROJECT_ID || '',
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
    privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
    bucket: process.env.FIREBASE_STORAGE_BUCKET || ''
  }
};


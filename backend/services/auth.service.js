import crypto from 'crypto';
import argon2 from 'argon2';
import { config } from '../config/config.js';

// Pre-computed dummy hash used for constant-time verification when a user is not found
// Generated with the exact same Argon2id parameters
let DUMMY_HASH = null;
(async () => {
  try {
    DUMMY_HASH = await argon2.hash('DummyTimingEqualizerPassword!2026', {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4
    });
  } catch (e) {
    // Fallback if needed
  }
})();

// Basic common passwords to reject
const COMMON_PASSWORDS = new Set([
  'password123', '1234567890', 'qwertyuiop', 'admin12345',
  'password2024', 'password2025', 'password2026', 'letmein123',
  'welcome123', 'iloveyou123', 'sunshine123', 'master1234'
]);

export class AuthService {
  /**
   * Hashes a password using Argon2id with OWASP-recommended parameters.
   */
  static async hashPassword(password) {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: 3,       // 3 iterations
      parallelism: 4     // 4 threads
    });
  }

  /**
   * Verifies a password against an Argon2id hash.
   */
  static async verifyPassword(hash, password) {
    try {
      return await argon2.verify(hash, password);
    } catch (e) {
      return false;
    }
  }

  /**
   * Runs a dummy verification in constant time when a user does not exist.
   * Eliminates user-enumeration timing side-channels.
   */
  static async dummyVerify(password) {
    try {
      if (!DUMMY_HASH) {
        DUMMY_HASH = await argon2.hash('DummyTimingEqualizerPassword!2026');
      }
      await argon2.verify(DUMMY_HASH, password);
    } catch (e) {
      // Ignored
    }
    return false;
  }

  /**
   * Validates password strength: min 10 chars, uppercase, lowercase, number, symbol.
   */
  static validatePasswordStrength(password) {
    if (!password || typeof password !== 'string') {
      return { valid: false, error: 'Password is required.' };
    }
    if (password.length < 10) {
      return { valid: false, error: 'Password must be at least 10 characters long.' };
    }
    if (password.length > 128) {
      return { valid: false, error: 'Password exceeds maximum length of 128 characters.' };
    }
    if (COMMON_PASSWORDS.has(password.toLowerCase())) {
      return { valid: false, error: 'This password is too common and easily guessed.' };
    }
    if (!/[A-Z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one uppercase letter.' };
    }
    if (!/[a-z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one lowercase letter.' };
    }
    if (!/[0-9]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one number.' };
    }
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one special character.' };
    }
    return { valid: true };
  }

  static lastGeneratedOtp = null;

  /**
   * Generates a cryptographically secure 6-digit uniform OTP.
   */
  static generateSecureOtp() {
    const num = crypto.randomInt(100000, 1000000);
    const otp = num.toString();
    if (process.env.NODE_ENV === 'test') {
      AuthService.lastGeneratedOtp = otp;
    }
    return otp;
  }

  /**
   * Computes HMAC-SHA256 of OTP bound to target ID and purpose.
   */
  static computeOtpHmac(otp, targetId, purpose) {
    const secret = config.auth.otpSecret;
    const payload = `${otp}:${targetId}:${purpose}`;
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
  }

  /**
   * Constant-time comparison between submitted OTP and stored HMAC.
   */
  static verifyOtpHmac(submittedOtp, targetId, purpose, storedHmac) {
    if (!submittedOtp || !storedHmac || submittedOtp.length !== 6) {
      return false;
    }
    const computedHmac = this.computeOtpHmac(submittedOtp, targetId, purpose);

    const a = Buffer.from(computedHmac, 'hex');
    const b = Buffer.from(storedHmac, 'hex');

    if (a.length !== b.length) {
      return false;
    }
    return crypto.timingSafeEqual(a, b);
  }

  /**
   * Masks an email address for safe client feedback (e.g., a***e@domain.com).
   */
  static maskEmail(email) {
    if (!email || !email.includes('@')) return '***@***';
    const [local, domain] = email.split('@');
    if (local.length <= 2) {
      return `${local[0]}*@${domain}`;
    }
    return `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}@${domain}`;
  }
}


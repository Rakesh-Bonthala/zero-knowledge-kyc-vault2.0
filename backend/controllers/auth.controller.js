import { UserModel } from '../models/user.model.js';
import { PendingRegistrationModel } from '../models/pendingRegistration.model.js';
import { OtpChallengeModel } from '../models/otpChallenge.model.js';
import { AuthService } from '../services/auth.service.js';
import { EmailService } from '../services/email.service.js';
import { generateCsrfToken } from '../middleware/csrf.middleware.js';
import { config } from '../config/config.js';

export class AuthController {
  /**
   * Generates and returns a CSRF token for frontend forms.
   */
  static async getCsrfToken(req, res) {
    try {
      const token = generateCsrfToken(req, res);
      res.json({
        success: true,
        csrfToken: token
      });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Failed to generate CSRF token.' });
    }
  }

  /**
   * Returns current authenticated user profile or unauthenticated status.
   */
  static async getMe(req, res) {
    if (!req.session || !req.session.userId) {
      return res.json({
        success: true,
        authenticated: false
      });
    }

    try {
      const user = await UserModel.findById(req.session.userId).select('-passwordHash').lean();
      if (!user || user.accountStatus !== 'active') {
        req.session.destroy(() => {});
        return res.json({ success: true, authenticated: false });
      }

      res.json({
        success: true,
        authenticated: true,
        user: {
          id: user._id.toString(),
          username: user.username,
          fullName: user.fullName,
          email: user.email
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Failed to retrieve session user.' });
    }
  }

  /**
   * Registration Step 1: Validate input, create pending registration, send OTP.
   */
  static async register(req, res, next) {
    try {
      const { fullName, username, email, password, confirmPassword, termsAccepted } = req.body;

      // 1. Mandatory input validations
      if (!fullName || !username || !email || !password || !confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'All fields are required.'
        });
      }

      if (termsAccepted !== true && termsAccepted !== 'true') {
        return res.status(400).json({
          success: false,
          error: 'You must review and accept the Terms of Service and Privacy Policy to proceed.'
        });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'Password and confirmation password do not match.'
        });
      }

      const trimmedName = String(fullName).trim();
      const trimmedUsername = String(username).trim();
      const trimmedEmail = String(email).trim();

      if (trimmedUsername.length < 3 || trimmedUsername.length > 30) {
        return res.status(400).json({
          success: false,
          error: 'Username must be between 3 and 30 characters.'
        });
      }

      if (!/^[a-zA-Z0-9_.-]+$/.test(trimmedUsername)) {
        return res.status(400).json({
          success: false,
          error: 'Username may only contain alphanumeric characters, underscores, dots, or hyphens.'
        });
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
        return res.status(400).json({
          success: false,
          error: 'Please enter a valid email address.'
        });
      }

      // 2. Validate password strength
      const strengthCheck = AuthService.validatePasswordStrength(password);
      if (!strengthCheck.valid) {
        return res.status(400).json({
          success: false,
          error: strengthCheck.error
        });
      }

      const usernameNormalized = trimmedUsername.toLowerCase();
      const emailNormalized = trimmedEmail.toLowerCase();

      // 3. Check uniqueness in users collection
      const existingUser = await UserModel.findOne({
        $or: [{ usernameNormalized }, { emailNormalized }]
      }).lean();

      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: existingUser.usernameNormalized === usernameNormalized
            ? 'That username is already taken. Please choose another.'
            : 'An account with that email address already exists.'
        });
      }

      // 4. Hash password with Argon2id
      const passwordHash = await AuthService.hashPassword(password);

      // 5. Create or update pending registration document
      const expiresAt = new Date(Date.now() + config.auth.pendingRegistrationExpiryMinutes * 60 * 1000);

      // Clean up any stale pending registration for this identifier
      await PendingRegistrationModel.deleteMany({
        $or: [{ usernameNormalized }, { emailNormalized }]
      });

      const pendingRecord = await PendingRegistrationModel.create({
        fullName: trimmedName,
        username: trimmedUsername,
        usernameNormalized,
        email: trimmedEmail,
        emailNormalized,
        passwordHash,
        termsAcceptedAt: new Date(),
        termsVersion: 'v1.0',
        expiresAt
      });

      const pendingId = pendingRecord._id.toString();

      // 6. Generate 6-digit OTP & create challenge
      const otp = AuthService.generateSecureOtp();
      const otpHmac = AuthService.computeOtpHmac(otp, pendingId, 'register');
      const otpExpiresAt = new Date(Date.now() + config.auth.otpExpiryMinutes * 60 * 1000);

      const challenge = await OtpChallengeModel.create({
        targetId: pendingId,
        targetType: 'pending_registration',
        email: emailNormalized,
        purpose: 'register',
        otpHmac,
        expiresAt: otpExpiresAt
      });

      // 7. Dispatch verification email (OTP is never logged)
      const emailResult = await EmailService.sendOtpEmail(trimmedEmail, otp, 'register');

      res.status(201).json({
        success: true,
        message: `A 6-digit verification code has been sent to ${AuthService.maskEmail(trimmedEmail)}.`,
        targetId: pendingId,
        challengeId: challenge._id.toString(),
        emailMasked: AuthService.maskEmail(trimmedEmail),
        purpose: 'register',
        expiresInSeconds: config.auth.otpExpiryMinutes * 60,
        devPreviewUrl: emailResult.previewUrl || null
      });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({
          success: false,
          error: 'An account or pending registration with those details already exists.'
        });
      }
      next(err);
    }
  }

  /**
   * Registration Step 2: Verify OTP and transition pending record to verified User.
   */
  static async verifyRegistrationOtp(req, res, next) {
    try {
      const { targetId, otp } = req.body;

      if (!targetId || !otp) {
        return res.status(400).json({
          success: false,
          error: 'Verification target ID and OTP are required.'
        });
      }

      // 1. Fetch pending registration
      const pending = await PendingRegistrationModel.findById(targetId);
      if (!pending) {
        return res.status(404).json({
          success: false,
          error: 'Registration session expired or not found. Please register again.'
        });
      }

      // 2. Fetch active OTP challenge
      const challenge = await OtpChallengeModel.findOne({
        targetId,
        purpose: 'register',
        used: false,
        expiresAt: { $gt: new Date() }
      }).sort({ createdAt: -1 });

      if (!challenge) {
        return res.status(400).json({
          success: false,
          error: 'Verification code expired or not found. Please request a new code.'
        });
      }

      if (challenge.attempts >= config.auth.maxOtpAttempts) {
        challenge.used = true;
        await challenge.save();
        return res.status(429).json({
          success: false,
          error: 'Maximum verification attempts exceeded. Please request a new code.'
        });
      }

      // 3. Constant-time comparison
      const isValid = AuthService.verifyOtpHmac(String(otp).trim(), targetId, 'register', challenge.otpHmac);

      if (!isValid) {
        challenge.attempts += 1;
        if (challenge.attempts >= config.auth.maxOtpAttempts) {
          challenge.used = true;
        }
        await challenge.save();

        const remaining = config.auth.maxOtpAttempts - challenge.attempts;
        return res.status(400).json({
          success: false,
          error: remaining > 0
            ? `Invalid verification code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
            : 'Invalid verification code. Maximum attempts reached.'
        });
      }

      // 4. Mark challenge used
      challenge.used = true;
      await challenge.save();

      // 5. Commit verified User to database
      const newUser = await UserModel.create({
        fullName: pending.fullName,
        username: pending.username,
        usernameNormalized: pending.usernameNormalized,
        email: pending.email,
        emailNormalized: pending.emailNormalized,
        passwordHash: pending.passwordHash,
        isEmailVerified: true,
        accountStatus: 'active',
        termsAcceptedAt: pending.termsAcceptedAt,
        termsVersion: pending.termsVersion
      });

      // 6. Remove pending record
      await PendingRegistrationModel.findByIdAndDelete(targetId);

      res.status(200).json({
        success: true,
        message: 'Account verified successfully! You can now log in.',
        user: {
          id: newUser._id.toString(),
          username: newUser.username,
          fullName: newUser.fullName,
          email: newUser.email
        }
      });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({
          success: false,
          error: 'An account with this username or email was already created.'
        });
      }
      next(err);
    }
  }

  /**
   * Resend OTP challenge for a pending registration or login.
   */
  static async resendOtp(req, res, next) {
    try {
      const { targetId, purpose } = req.body;

      if (!targetId || !purpose) {
        return res.status(400).json({
          success: false,
          error: 'Target ID and purpose are required.'
        });
      }

      let email = '';
      if (purpose === 'register') {
        const pending = await PendingRegistrationModel.findById(targetId);
        if (!pending) {
          return res.status(404).json({ success: false, error: 'Registration request not found.' });
        }
        email = pending.email;
      } else {
        const user = await UserModel.findById(targetId);
        if (!user) {
          return res.status(404).json({ success: false, error: 'Account not found.' });
        }
        email = user.email;
      }

      // Check cooldown on latest challenge
      const lastChallenge = await OtpChallengeModel.findOne({
        targetId,
        purpose
      }).sort({ createdAt: -1 });

      if (lastChallenge) {
        const secondsSinceLast = Math.floor((Date.now() - new Date(lastChallenge.lastSentAt).getTime()) / 1000);
        if (secondsSinceLast < config.auth.resendCooldownSeconds) {
          const waitSeconds = config.auth.resendCooldownSeconds - secondsSinceLast;
          return res.status(429).json({
            success: false,
            error: `Please wait ${waitSeconds} second${waitSeconds === 1 ? '' : 's'} before requesting a new code.`
          });
        }
      }

      // Invalidate all previous unused challenges for this target + purpose
      await OtpChallengeModel.updateMany({ targetId, purpose, used: false }, { used: true });

      // Generate new 6-digit OTP
      const otp = AuthService.generateSecureOtp();
      const otpHmac = AuthService.computeOtpHmac(otp, targetId, purpose);
      const otpExpiresAt = new Date(Date.now() + config.auth.otpExpiryMinutes * 60 * 1000);

      const challenge = await OtpChallengeModel.create({
        targetId,
        targetType: purpose === 'register' ? 'pending_registration' : 'user',
        email: email.toLowerCase(),
        purpose,
        otpHmac,
        lastSentAt: new Date(),
        expiresAt: otpExpiresAt
      });

      const emailResult = await EmailService.sendOtpEmail(email, otp, purpose);

      res.json({
        success: true,
        message: `A fresh verification code has been sent to ${AuthService.maskEmail(email)}.`,
        targetId,
        challengeId: challenge._id.toString(),
        emailMasked: AuthService.maskEmail(email),
        purpose,
        expiresInSeconds: config.auth.otpExpiryMinutes * 60,
        devPreviewUrl: emailResult.previewUrl || null
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Login Step 1: Verify username/email and password, issue OTP.
   */
  static async login(req, res, next) {
    try {
      const { identifier, password } = req.body;

      if (!identifier || !password) {
        return res.status(400).json({
          success: false,
          error: 'Username/email and password are required.'
        });
      }

      const normalized = String(identifier).trim().toLowerCase();

      // Find user by username or email
      const user = await UserModel.findOne({
        $or: [{ usernameNormalized: normalized }, { emailNormalized: normalized }]
      });

      // Timing equalizer if user doesn't exist
      if (!user) {
        await AuthService.dummyVerify(password);
        return res.status(401).json({
          success: false,
          error: 'Invalid username/email or password.'
        });
      }

      // Check account lockout status
      if (user.accountStatus === 'locked' && user.lockedUntil && user.lockedUntil > new Date()) {
        const remainingMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / (60 * 1000));
        return res.status(423).json({
          success: false,
          error: `Account is temporarily locked due to consecutive failed attempts. Try again in ${remainingMinutes} minute${remainingMinutes === 1 ? '' : 's'}.`
        });
      } else if (user.accountStatus === 'locked' && user.lockedUntil && user.lockedUntil <= new Date()) {
        // Lock expired
        user.accountStatus = 'active';
        user.failedLoginCount = 0;
        user.lockedUntil = null;
        await user.save();
      }

      if (user.accountStatus === 'disabled') {
        return res.status(403).json({
          success: false,
          error: 'This account has been disabled. Please contact support.'
        });
      }

      // Verify Argon2id password
      const passwordMatch = await AuthService.verifyPassword(user.passwordHash, password);

      if (!passwordMatch) {
        user.failedLoginCount += 1;
        if (user.failedLoginCount >= config.auth.accountLockoutThreshold) {
          user.accountStatus = 'locked';
          user.lockedUntil = new Date(Date.now() + config.auth.accountLockoutDurationMinutes * 60 * 1000);
        }
        await user.save();

        return res.status(401).json({
          success: false,
          error: 'Invalid username/email or password.'
        });
      }

      // Password matches: reset failed count
      user.failedLoginCount = 0;
      await user.save();

      // Issue Login OTP challenge
      const userId = user._id.toString();
      await OtpChallengeModel.updateMany({ targetId: userId, purpose: 'login', used: false }, { used: true });

      const otp = AuthService.generateSecureOtp();
      const otpHmac = AuthService.computeOtpHmac(otp, userId, 'login');
      const otpExpiresAt = new Date(Date.now() + config.auth.otpExpiryMinutes * 60 * 1000);

      const challenge = await OtpChallengeModel.create({
        targetId: userId,
        targetType: 'user',
        email: user.emailNormalized,
        purpose: 'login',
        otpHmac,
        expiresAt: otpExpiresAt
      });

      const emailResult = await EmailService.sendOtpEmail(user.email, otp, 'login');

      res.json({
        success: true,
        requiresOtp: true,
        message: `Verification code sent to ${AuthService.maskEmail(user.email)}.`,
        targetId: userId,
        challengeId: challenge._id.toString(),
        emailMasked: AuthService.maskEmail(user.email),
        purpose: 'login',
        expiresInSeconds: config.auth.otpExpiryMinutes * 60,
        devPreviewUrl: emailResult.previewUrl || null
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Login Step 2: Verify login OTP, regenerate session, authenticate user.
   */
  static async verifyLoginOtp(req, res, next) {
    try {
      const { targetId, otp } = req.body;

      if (!targetId || !otp) {
        return res.status(400).json({
          success: false,
          error: 'Target ID and verification code are required.'
        });
      }

      const user = await UserModel.findById(targetId);
      if (!user || user.accountStatus !== 'active') {
        return res.status(401).json({
          success: false,
          error: 'Authentication failed or account inactive.'
        });
      }

      const challenge = await OtpChallengeModel.findOne({
        targetId,
        purpose: 'login',
        used: false,
        expiresAt: { $gt: new Date() }
      }).sort({ createdAt: -1 });

      if (!challenge) {
        return res.status(400).json({
          success: false,
          error: 'Verification code expired or not found. Please sign in again.'
        });
      }

      if (challenge.attempts >= config.auth.maxOtpAttempts) {
        challenge.used = true;
        await challenge.save();
        return res.status(429).json({
          success: false,
          error: 'Maximum verification attempts exceeded. Please sign in again.'
        });
      }

      const isValid = AuthService.verifyOtpHmac(String(otp).trim(), targetId, 'login', challenge.otpHmac);

      if (!isValid) {
        challenge.attempts += 1;
        if (challenge.attempts >= config.auth.maxOtpAttempts) {
          challenge.used = true;
        }
        await challenge.save();

        const remaining = config.auth.maxOtpAttempts - challenge.attempts;
        return res.status(400).json({
          success: false,
          error: remaining > 0
            ? `Invalid verification code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
            : 'Invalid verification code. Maximum attempts reached.'
        });
      }

      challenge.used = true;
      await challenge.save();

      // Session regeneration to prevent session fixation attacks
      req.session.regenerate((err) => {
        if (err) return next(err);

        req.session.userId = user._id.toString();
        req.session.username = user.username;
        req.session.email = user.email;

        res.json({
          success: true,
          message: 'Authentication successful.',
          user: {
            id: user._id.toString(),
            username: user.username,
            fullName: user.fullName,
            email: user.email
          }
        });
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Request password reset code (Generic response to avoid user enumeration).
   */
  static async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;

      if (!email || !String(email).includes('@')) {
        return res.status(400).json({
          success: false,
          error: 'Please enter a valid email address.'
        });
      }

      const normalized = String(email).trim().toLowerCase();
      const user = await UserModel.findOne({ emailNormalized: normalized });

      if (user && user.accountStatus === 'active') {
        const userId = user._id.toString();
        await OtpChallengeModel.updateMany({ targetId: userId, purpose: 'reset', used: false }, { used: true });

        const otp = AuthService.generateSecureOtp();
        const otpHmac = AuthService.computeOtpHmac(otp, userId, 'reset');
        const otpExpiresAt = new Date(Date.now() + config.auth.otpExpiryMinutes * 60 * 1000);

        const challenge = await OtpChallengeModel.create({
          targetId: userId,
          targetType: 'user',
          email: user.emailNormalized,
          purpose: 'reset',
          otpHmac,
          expiresAt: otpExpiresAt
        });

        const emailResult = await EmailService.sendOtpEmail(user.email, otp, 'reset');

        return res.json({
          success: true,
          message: 'If an account exists with that email, a password reset code has been sent.',
          targetId: userId,
          challengeId: challenge._id.toString(),
          emailMasked: AuthService.maskEmail(user.email),
          purpose: 'reset',
          expiresInSeconds: config.auth.otpExpiryMinutes * 60,
          devPreviewUrl: emailResult.previewUrl || null
        });
      }

      // Generic response even if user doesn't exist
      res.json({
        success: true,
        message: 'If an account exists with that email, a password reset code has been sent.'
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Reset password using verified OTP and new password.
   */
  static async resetPassword(req, res, next) {
    try {
      const { targetId, otp, newPassword, confirmPassword } = req.body;

      if (!targetId || !otp || !newPassword || !confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'All fields are required.'
        });
      }

      if (newPassword !== confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'New password and confirmation do not match.'
        });
      }

      const strengthCheck = AuthService.validatePasswordStrength(newPassword);
      if (!strengthCheck.valid) {
        return res.status(400).json({
          success: false,
          error: strengthCheck.error
        });
      }

      const user = await UserModel.findById(targetId);
      if (!user) {
        return res.status(400).json({
          success: false,
          error: 'Invalid password reset request.'
        });
      }

      const challenge = await OtpChallengeModel.findOne({
        targetId,
        purpose: 'reset',
        used: false,
        expiresAt: { $gt: new Date() }
      }).sort({ createdAt: -1 });

      if (!challenge) {
        return res.status(400).json({
          success: false,
          error: 'Reset code expired or not found. Please request a new code.'
        });
      }

      const isValid = AuthService.verifyOtpHmac(String(otp).trim(), targetId, 'reset', challenge.otpHmac);
      if (!isValid) {
        challenge.attempts += 1;
        if (challenge.attempts >= config.auth.maxOtpAttempts) challenge.used = true;
        await challenge.save();

        return res.status(400).json({
          success: false,
          error: 'Invalid verification code.'
        });
      }

      challenge.used = true;
      await challenge.save();

      // Hash new password with Argon2id
      user.passwordHash = await AuthService.hashPassword(newPassword);
      user.failedLoginCount = 0;
      user.lockedUntil = null;
      if (user.accountStatus === 'locked') user.accountStatus = 'active';
      await user.save();

      // Terminate any active sessions for the user if using MongoStore
      if (req.sessionStore && typeof req.sessionStore.destroy === 'function') {
        // Destroy current session
        req.session.destroy(() => {});
      }

      // Send security alert notification
      await EmailService.sendPasswordChangedNotification(user.email);

      res.json({
        success: true,
        message: 'Password successfully updated. You may now sign in with your new password.'
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * Log out user: destroy server session and clear cookie.
   */
  static async logout(req, res) {
    if (req.session) {
      req.session.destroy((err) => {
        res.clearCookie(config.auth.sessionName, {
          path: '/',
          httpOnly: true,
          sameSite: 'lax',
          secure: config.nodeEnv === 'production'
        });
        res.json({
          success: true,
          message: 'Signed out successfully.'
        });
      });
    } else {
      res.json({ success: true, message: 'Signed out successfully.' });
    }
  }
}


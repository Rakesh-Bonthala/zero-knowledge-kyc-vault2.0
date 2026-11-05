import express from 'express';
import { AuthController } from '../controllers/auth.controller.js';
import {
  authRateLimiter,
  otpVerificationLimiter,
  otpResendLimiter
} from '../middleware/rateLimit.middleware.js';
import { doubleCsrfProtection } from '../middleware/csrf.middleware.js';

const router = express.Router();

// Public session queries
router.get('/csrf-token', AuthController.getCsrfToken);
router.get('/me', AuthController.getMe);

// Registration flow
router.post(
  '/register',
  authRateLimiter,
  doubleCsrfProtection,
  AuthController.register
);

router.post(
  '/verify-registration-otp',
  otpVerificationLimiter,
  doubleCsrfProtection,
  AuthController.verifyRegistrationOtp
);

// Login flow
router.post(
  '/login',
  authRateLimiter,
  doubleCsrfProtection,
  AuthController.login
);

router.post(
  '/verify-login-otp',
  otpVerificationLimiter,
  doubleCsrfProtection,
  AuthController.verifyLoginOtp
);

// Resend OTP
router.post(
  '/resend-otp',
  otpResendLimiter,
  doubleCsrfProtection,
  AuthController.resendOtp
);

// Password Reset flow
router.post(
  '/forgot-password',
  authRateLimiter,
  doubleCsrfProtection,
  AuthController.forgotPassword
);

router.post(
  '/reset-password',
  otpVerificationLimiter,
  doubleCsrfProtection,
  AuthController.resetPassword
);

// Logout
router.post(
  '/logout',
  doubleCsrfProtection,
  AuthController.logout
);

export default router;


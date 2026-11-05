import rateLimit from 'express-rate-limit';

// Standard error payload for rate-limit breaches
const rateLimitHandler = (req, res, next, options) => {
  res.status(429).json({
    success: false,
    error: 'Too many requests. Please wait a few moments before trying again.',
    code: 'RATE_LIMIT_EXCEEDED'
  });
};

/**
 * Rate limiter for sensitive authentication endpoints (registration, login)
 * 15 requests per 15 minutes per IP
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler
});

/**
 * Rate limiter for OTP verification attempts
 * 15 requests per 15 minutes per IP
 */
export const otpVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler
});

/**
 * Rate limiter for OTP resend triggers
 * Max 6 resends per 15 minutes
 */
export const otpResendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: 'You have reached the limit for resending verification codes. Please wait before requesting another.',
      code: 'OTP_RESEND_LIMIT_EXCEEDED'
    });
  }
});


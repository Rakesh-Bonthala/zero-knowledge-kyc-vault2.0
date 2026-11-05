import { doubleCsrf } from 'csrf-csrf';
import { config } from '../config/config.js';

const csrfUtilities = doubleCsrf({
  getSecret: () => config.auth.csrfSecret,
  getSessionIdentifier: (req) => req.session?.userId || 'anonymous_guest',
  cookieName: 'zk_vault_csrf',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: config.nodeEnv === 'production'
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getTokenFromRequest: (req) =>
    req.headers['x-csrf-token'] || req.headers['x-xsrf-token'] || req.body?._csrf
});

export const {
  invalidCsrfTokenError,
  generateCsrfToken,
  validateRequest,
  doubleCsrfProtection
} = csrfUtilities;

/**
 * Lightweight cookie parser middleware
 */
export function cookieParserMiddleware(req, res, next) {
  req.cookies = req.cookies || {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const pairs = cookieHeader.split(';');
    for (const pair of pairs) {
      const idx = pair.indexOf('=');
      if (idx !== -1) {
        const key = pair.slice(0, idx).trim();
        const val = pair.slice(idx + 1).trim();
        try {
          req.cookies[key] = decodeURIComponent(val);
        } catch {
          req.cookies[key] = val;
        }
      }
    }
  }
  next();
}

/**
 * Session Authentication Middleware
 * Enforces authenticated server-side session for protected vault routes.
 */
export function requireSessionAuth(req, res, next) {
  // Enforce active session
  if (req.session && req.session.userId) {
    req.user = {
      id: String(req.session.userId),
      username: req.session.username,
      email: req.session.email
    };
    return next();
  }

  // Graceful test fallback for automated unit testing suites
  if (process.env.NODE_ENV === 'test' && req.headers['x-user-id']) {
    const sanitizedUserId = String(req.headers['x-user-id']).trim().replace(/[^a-zA-Z0-9_-]/g, '');
    if (sanitizedUserId) {
      req.user = { id: sanitizedUserId };
      return next();
    }
  }

  return res.status(401).json({
    success: false,
    error: 'Authentication required. Please sign in to access your vault.',
    code: 'UNAUTHENTICATED'
  });
}

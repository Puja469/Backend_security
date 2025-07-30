const crypto = require('crypto');

// CSRF token storage (in production, use Redis or database)
const csrfTokens = new Map();

// CSRF Configuration
const CSRF_CONFIG = {
  tokenLength: 32,
  cookieName: 'csrf-token',
  headerName: 'X-CSRF-Token',
  cookieOptions: {
    httpOnly: false, // Must be false for frontend to read
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/'
  },
  sessionTimeout: 24 * 60 * 60 * 1000 // 24 hours
};

// Generate a random CSRF token
const generateCSRFToken = () => {
  return crypto.randomBytes(CSRF_CONFIG.tokenLength).toString('hex');
};

// Store CSRF token with session info
const storeCSRFToken = (token, userId = null) => {
  const expiresAt = Date.now() + CSRF_CONFIG.sessionTimeout;
  csrfTokens.set(token, {
    userId,
    expiresAt,
    createdAt: Date.now()
  });
  
  // Clean up expired tokens periodically
  cleanupExpiredTokens();
};

// Get CSRF token info
const getCSRFToken = (token) => {
  const tokenInfo = csrfTokens.get(token);
  if (!tokenInfo) return null;
  
  // Check if token is expired
  if (Date.now() > tokenInfo.expiresAt) {
    csrfTokens.delete(token);
    return null;
  }
  
  return tokenInfo;
};

// Clean up expired tokens
const cleanupExpiredTokens = () => {
  const now = Date.now();
  for (const [token, info] of csrfTokens.entries()) {
    if (now > info.expiresAt) {
      csrfTokens.delete(token);
    }
  }
};

// Generate and send CSRF token middleware
const generateCSRFTokenMiddleware = (req, res, next) => {
  try {
    // Generate new CSRF token
    const csrfToken = generateCSRFToken();
    
    // Get user ID if authenticated
    const userId = req.user ? req.user._id : null;
    
    // Store token with user info
    storeCSRFToken(csrfToken, userId);
    
    // Set CSRF token in cookie
    res.cookie(CSRF_CONFIG.cookieName, csrfToken, CSRF_CONFIG.cookieOptions);
    
    // Add token to response headers for frontend access
    res.setHeader('X-CSRF-Token', csrfToken);
    
    // Add token to response body for API responses
    if (req.path.includes('/api/')) {
      res.locals.csrfToken = csrfToken;
    }
    
    next();
  } catch (error) {
    console.error('CSRF token generation error:', error);
    next();
  }
};

// Validate CSRF token middleware
const validateCSRFTokenMiddleware = (req, res, next) => {
  // Only validate for sensitive HTTP methods
  const sensitiveMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
  if (!sensitiveMethods.includes(req.method)) {
    return next();
  }
  
  try {
    // Get token from header (preferred method)
    let csrfToken = req.headers[CSRF_CONFIG.headerName.toLowerCase()];
    
    // Fallback to cookie if not in header
    if (!csrfToken && req.cookies) {
      csrfToken = req.cookies[CSRF_CONFIG.cookieName];
    }
    
    // Check if token exists
    if (!csrfToken) {
      return res.status(403).json({
        status: 'error',
        message: 'CSRF token missing. Please refresh the page and try again.',
        code: 'CSRF_TOKEN_MISSING'
      });
    }
    
    // Validate token
    const tokenInfo = getCSRFToken(csrfToken);
    if (!tokenInfo) {
      return res.status(403).json({
        status: 'error',
        message: 'Invalid or expired CSRF token. Please refresh the page and try again.',
        code: 'CSRF_TOKEN_INVALID'
      });
    }
    
    // Optional: Check if token belongs to authenticated user
    if (req.user && tokenInfo.userId && tokenInfo.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        status: 'error',
        message: 'CSRF token mismatch. Please refresh the page and try again.',
        code: 'CSRF_TOKEN_MISMATCH'
      });
    }
    
    // Token is valid, proceed
    req.csrfToken = csrfToken;
    req.csrfTokenInfo = tokenInfo;
    next();
    
  } catch (error) {
    console.error('CSRF validation error:', error);
    return res.status(500).json({
      status: 'error',
      message: 'CSRF validation failed. Please try again.',
      code: 'CSRF_VALIDATION_ERROR'
    });
  }
};

// Refresh CSRF token middleware (for token renewal)
const refreshCSRFTokenMiddleware = (req, res, next) => {
  try {
    // Remove old token if exists
    const oldToken = req.cookies[CSRF_CONFIG.cookieName];
    if (oldToken) {
      csrfTokens.delete(oldToken);
    }
    
    // Generate new token
    const newToken = generateCSRFToken();
    const userId = req.user ? req.user._id : null;
    storeCSRFToken(newToken, userId);
    
    // Set new token in cookie
    res.cookie(CSRF_CONFIG.cookieName, newToken, CSRF_CONFIG.cookieOptions);
    
    // Add to response
    res.locals.csrfToken = newToken;
    res.setHeader('X-CSRF-Token', newToken);
    
    next();
  } catch (error) {
    console.error('CSRF token refresh error:', error);
    next();
  }
};

// Get CSRF token info (for debugging/admin)
const getCSRFTokenInfo = (token) => {
  return getCSRFToken(token);
};

// Get all active CSRF tokens (for debugging/admin)
const getAllCSRFTokens = () => {
  const activeTokens = [];
  for (const [token, info] of csrfTokens.entries()) {
    if (Date.now() <= info.expiresAt) {
      activeTokens.push({
        token: token.substring(0, 8) + '...', // Partial token for security
        userId: info.userId,
        createdAt: info.createdAt,
        expiresAt: info.expiresAt
      });
    }
  }
  return activeTokens;
};

// Clear all CSRF tokens (for logout/cleanup)
const clearAllCSRFTokens = () => {
  csrfTokens.clear();
};

// Clear tokens for specific user (for logout)
const clearUserCSRFTokens = (userId) => {
  for (const [token, info] of csrfTokens.entries()) {
    if (info.userId && info.userId.toString() === userId.toString()) {
      csrfTokens.delete(token);
    }
  }
};

module.exports = {
  generateCSRFTokenMiddleware,
  validateCSRFTokenMiddleware,
  refreshCSRFTokenMiddleware,
  getCSRFTokenInfo: getCSRFToken,
  getAllCSRFTokens,
  clearAllCSRFTokens,
  clearUserCSRFTokens,
  storeCSRFToken,
  CSRF_CONFIG
}; 
const crypto = require('crypto');
const {
  getAllCSRFTokens,
  clearAllCSRFTokens,
  clearUserCSRFTokens,
  CSRF_CONFIG
} = require('../middleware/csrf');

// Get CSRF token (for frontend)
const getCSRFToken = async (req, res) => {
  try {
    // Generate new CSRF token
    const csrfToken = crypto.randomBytes(CSRF_CONFIG.tokenLength).toString('hex');

    // Get user ID if authenticated
    const userId = req.user ? req.user._id : null;

    // Store token with user info
    const { storeCSRFToken } = require('../middleware/csrf');
    storeCSRFToken(csrfToken, userId);

    // Set CSRF token in cookie
    res.cookie(CSRF_CONFIG.cookieName, csrfToken, CSRF_CONFIG.cookieOptions);

    // Add token to response headers
    res.setHeader('X-CSRF-Token', csrfToken);

    res.status(200).json({
      status: 'success',
      message: 'CSRF token generated successfully',
      data: {
        token: csrfToken,
        expiresIn: CSRF_CONFIG.sessionTimeout,
        headerName: CSRF_CONFIG.headerName,
        cookieName: CSRF_CONFIG.cookieName
      }
    });
  } catch (error) {
    console.error('CSRF token generation error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to generate CSRF token',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
};

// Refresh CSRF token
const refreshCSRFToken = async (req, res) => {
  try {
    // Remove old token if exists
    const oldToken = req.cookies[CSRF_CONFIG.cookieName];
    if (oldToken) {
      const { clearUserCSRFTokens } = require('../middleware/csrf');
      // Clear old token (this is a simplified approach)
      clearUserCSRFTokens(req.user ? req.user._id : null);
    }

    // Generate new token
    const csrfToken = crypto.randomBytes(CSRF_CONFIG.tokenLength).toString('hex');
    const userId = req.user ? req.user._id : null;

    // Store new token
    const { storeCSRFToken } = require('../middleware/csrf');
    storeCSRFToken(csrfToken, userId);

    // Set new token in cookie
    res.cookie(CSRF_CONFIG.cookieName, csrfToken, CSRF_CONFIG.cookieOptions);

    // Add to response headers
    res.setHeader('X-CSRF-Token', csrfToken);

    res.status(200).json({
      status: 'success',
      message: 'CSRF token refreshed successfully',
      data: {
        token: csrfToken,
        expiresIn: CSRF_CONFIG.sessionTimeout
      }
    });
  } catch (error) {
    console.error('CSRF token refresh error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to refresh CSRF token',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
};

// Validate CSRF token (for testing)
const validateCSRFToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        status: 'error',
        message: 'CSRF token is required'
      });
    }

    // Check if token is provided in header (this is what the middleware checks)
    const headerToken = req.headers['x-csrf-token'];
    if (!headerToken) {
      return res.status(403).json({
        status: 'error',
        message: 'CSRF token missing in header. Please include X-CSRF-Token header.',
        code: 'CSRF_TOKEN_MISSING'
      });
    }

    // Check if header token matches body token
    if (headerToken !== token) {
      return res.status(403).json({
        status: 'error',
        message: 'CSRF token mismatch between header and body',
        code: 'CSRF_TOKEN_MISMATCH'
      });
    }

    const { getCSRFTokenInfo } = require('../middleware/csrf');
    const tokenInfo = getCSRFTokenInfo(token);

    if (!tokenInfo) {
      return res.status(403).json({
        status: 'error',
        message: 'Invalid or expired CSRF token',
        code: 'CSRF_TOKEN_INVALID'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'CSRF token is valid',
      data: {
        isValid: true,
        userId: tokenInfo.userId,
        createdAt: tokenInfo.createdAt,
        expiresAt: tokenInfo.expiresAt
      }
    });
  } catch (error) {
    console.error('CSRF token validation error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to validate CSRF token',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
};

// Get CSRF token status (for admin/debugging)
const getCSRFStatus = async (req, res) => {
  try {
    const activeTokens = getAllCSRFTokens();

    res.status(200).json({
      status: 'success',
      message: 'CSRF token status retrieved successfully',
      data: {
        activeTokensCount: activeTokens.length,
        tokens: activeTokens,
        config: {
          tokenLength: CSRF_CONFIG.tokenLength,
          sessionTimeout: CSRF_CONFIG.sessionTimeout,
          cookieName: CSRF_CONFIG.cookieName,
          headerName: CSRF_CONFIG.headerName
        }
      }
    });
  } catch (error) {
    console.error('CSRF status error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to get CSRF status',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
};

// Clear CSRF tokens (for admin/debugging)
const clearCSRFTokens = async (req, res) => {
  try {
    const { userId } = req.body;

    if (userId) {
      // Clear tokens for specific user
      clearUserCSRFTokens(userId);
      res.status(200).json({
        status: 'success',
        message: `CSRF tokens cleared for user ${userId}`
      });
    } else {
      // Clear all tokens
      clearAllCSRFTokens();
      res.status(200).json({
        status: 'success',
        message: 'All CSRF tokens cleared'
      });
    }
  } catch (error) {
    console.error('CSRF token clear error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to clear CSRF tokens',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
};

module.exports = {
  getCSRFToken,
  refreshCSRFToken,
  validateCSRFToken,
  getCSRFStatus,
  clearCSRFTokens
}; 
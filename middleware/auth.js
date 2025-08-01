const jwt = require("jsonwebtoken");
const asyncHandler = require("./async");
const User = require("../model/User");
const Credential = require("../model/Credential");

exports.protect = asyncHandler(async (req, res, next) => {
  let token;

  // 1. Get token from header (Bearer) or cookies
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    // From Authorization Header
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.token) {
    // From HttpOnly Cookie
    token = req.cookies.token;
  }

  // 2. Token not found
  if (!token) {
    return res.status(401).json({
      status: 'error',
      message: "Not authorized. No token provided."
    });
  }

  try {

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'thriftstore-api',
      audience: 'thriftstore-client'
    });

    // 4. Check if user/admin still exists (check both models)
    let user = await User.findById(decoded.id).select("-password");
    let isAdmin = false;

    if (!user) {
      // If not found in User model, check Credential model (admin)
      const admin = await Credential.findById(decoded.id);
      if (admin) {
        user = admin;
        isAdmin = true;
      }
    }

    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: "User not found or token invalid."
      });
    }


    if (!isAdmin && user.passwordChangedAt) {
      const changedTimestamp = parseInt(
        user.passwordChangedAt.getTime() / 1000,
        10
      );

      if (decoded.iat < changedTimestamp) {
        return res.status(401).json({
          status: 'error',
          message: "User recently changed password! Please log in again."
        });
      }
    }


    if (!isAdmin && decoded.sessionVersion && user.sessionVersion) {
      if (decoded.sessionVersion < user.sessionVersion) {
        return res.status(401).json({
          status: 'error',
          message: "Session expired. Please log in again."
        });
      }
    }


    if (!isAdmin && !user.isActive) {
      return res.status(401).json({
        status: 'error',
        message: "User account is deactivated."
      });
    }


    if (!isAdmin && user.isAccountLocked) {
      const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(423).json({
        status: 'error',
        message: `Account is locked due to multiple failed login attempts. Try again in ${lockTimeRemaining} minutes.`
      });
    }

    // Check if user is blocked by admin
    if (!isAdmin && user.isBlocked) {
      return res.status(403).json({
        status: 'error',
        message: `Account has been blocked by administrator. Reason: ${user.blockReason || 'No reason provided'}. Contact support for assistance.`
      });
    }

    // Grant access to protected route
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        status: 'error',
        message: "Invalid token."
      });
    } else if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'error',
        message: "Token expired. Please log in again."
      });
    }

    return res.status(401).json({
      status: 'error',
      message: "Not authorized. Token failed."
    });
  }
});


exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        message: "User not authenticated."
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        message: `Access denied. Role '${req.user.role}' is not authorized.`,
      });
    }
    next();
  };
};

// =============================================
// Optional authentication middleware
// =============================================
exports.optionalAuth = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: 'thriftstore-api',
        audience: 'thriftstore-client'
      });

      const user = await User.findById(decoded.id).select("-password");
      if (user && user.isActive && !user.isAccountLocked) {
        req.user = user;
      }
    } catch (err) {
      // Token is invalid, but we don't block the request
      console.log('Optional auth failed:', err.message);
    }
  }

  next();
});

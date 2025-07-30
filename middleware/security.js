const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const requestValidator = require('./requestValidator');

// Rate limiting for different endpoints
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      status: 429,
      message
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        status: 'error',
        message: message
      });
    }
  });
};

// General API rate limiter
const apiLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  500, // 500 requests per window (increased from 100)
  'Too many requests from this IP, please try again later.'
);

// Strict rate limiter for auth endpoints
const authLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts per window
  'Too many authentication attempts, please try again later.'
);

// Speed limiter to prevent brute force
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // Allow 50 requests per 15 minutes without delay
  delayMs: (used, req) => {
    const delayAfter = req.slowDown.limit;
    return (used - delayAfter) * 500;
  },
  validate: { delayMs: false } // Disable validation warning
});

// File upload rate limiter
const uploadLimiter = createRateLimiter(
  60 * 60 * 1000, // 1 hour
  10, // 10 uploads per hour
  'Too many file uploads, please try again later.'
);

// Product creation rate limiter (more lenient)
const productCreationLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  50, // 50 product creations per 15 minutes
  'Too many product creation attempts, please try again later.'
);

// Sanitize data
const sanitizeData = mongoSanitize();

// Prevent XSS attacks
const preventXSS = xss();

// Prevent HTTP Parameter Pollution
const preventHPP = hpp({
  whitelist: ['category', 'subcategory', 'price', 'sort'] // Allow these parameters to be duplicated
});

// Request validation middleware
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid request data',
        details: error.details.map(detail => detail.message)
      });
    }
    next();
  };
};

// Check for suspicious activity
const detectSuspiciousActivity = (req, res, next) => {
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /document\./i,
    /window\./i
  ];

  const userInput = JSON.stringify(req.body) + JSON.stringify(req.query) + JSON.stringify(req.params);

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(userInput)) {
      return res.status(400).json({
        status: 'error',
        message: 'Suspicious activity detected'
      });
    }
  }

  next();
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
};

module.exports = {
  apiLimiter,
  authLimiter,
  speedLimiter,
  uploadLimiter,
  productCreationLimiter,
  sanitizeData,
  preventXSS,
  preventHPP,
  validateRequest,
  detectSuspiciousActivity,
  securityHeaders,
  requestValidator
}; 
const express = require("express");
const router = express.Router();
const { 
  getCSRFToken, 
  refreshCSRFToken, 
  validateCSRFToken, 
  getCSRFStatus, 
  clearCSRFTokens 
} = require("../controller/CSRFController");

// Security middleware imports
const {
  apiLimiter,
  sanitizeData,
  preventXSS,
  preventHPP,
  detectSuspiciousActivity,
  securityHeaders
} = require("../middleware/security");
const { protect, authorize } = require("../middleware/auth");
const { validateCSRFTokenMiddleware } = require("../middleware/csrf");
const activityLogger = require("../middleware/activityLogger");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// Public CSRF token endpoints
router.get("/token",  activityLogger("Requested CSRF token"), getCSRFToken);
router.post("/validate", apiLimiter, activityLogger("Validated CSRF token"), validateCSRFToken);

// Protected CSRF token endpoints (require authentication)
router.post("/refresh", apiLimiter, protect, validateCSRFTokenMiddleware, activityLogger("Refreshed CSRF token"), refreshCSRFToken);

// Admin-only CSRF management endpoints
router.get("/status", apiLimiter, protect, authorize('admin'), activityLogger("Viewed CSRF status"), getCSRFStatus);
router.delete("/clear", apiLimiter, protect, authorize('admin'), validateCSRFTokenMiddleware, activityLogger("Cleared CSRF tokens"), clearCSRFTokens);

module.exports = router; 
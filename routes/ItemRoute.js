const express = require("express");
const router = express.Router();
const { findAll, save, findById, deleteById, update, incrementViewCount, getViewCount, updateStatus } = require("../controller/ItemController");

// Security middleware imports
const {
    apiLimiter,
    uploadLimiter,
    productCreationLimiter,
    sanitizeData,
    preventXSS,
    preventHPP,
    detectSuspiciousActivity,
    securityHeaders,
    validateRequest
} = require("../middleware/security");
const { protect, authorize, optionalAuth } = require("../middleware/auth");
const { validateCSRFTokenMiddleware } = require("../middleware/csrf");
const upload = require("../middleware/upload");
const activityLogger = require("../middleware/activityLogger");
const { itemCreationSchema } = require("../validation/securityValidation");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// Regular API calls - NO rate limiting needed (strategic approach)
router.get("/", optionalAuth, activityLogger("Viewed all items"), findAll);
router.get("/:id", optionalAuth, activityLogger("Viewed item by ID"), findById);
router.get("/:id/view-count", getViewCount);
router.put("/:id/status", protect, validateCSRFTokenMiddleware, activityLogger("Updated item status"), updateStatus);
router.post("/:id/increment-view", incrementViewCount);

// File uploads - need rate limiting
router.post("/", productCreationLimiter, protect, uploadLimiter, upload, validateRequest(itemCreationSchema), validateCSRFTokenMiddleware, activityLogger("Created new item"), save);
router.put("/:id", protect, uploadLimiter, upload, validateCSRFTokenMiddleware, activityLogger("Updated item"), update);

// Simple operations - NO rate limiting needed
router.delete("/:id", protect, validateCSRFTokenMiddleware, activityLogger("Deleted item"), deleteById);

module.exports = router;
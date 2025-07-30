const express = require("express");
const router = express.Router();
const { findAll, save, findById, deleteById, update } = require("../controller/SubCategoryController");

// Security middleware imports
const {
    apiLimiter,
    sanitizeData,
    preventXSS,
    preventHPP,
    detectSuspiciousActivity,
    securityHeaders,
    validateRequest
} = require("../middleware/security");
const { protect, authorize } = require("../middleware/auth");
const activityLogger = require("../middleware/activityLogger");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// Public routes (read-only)
router.get("/", apiLimiter, activityLogger("Viewed all subcategories"), findAll);
router.get("/:id", apiLimiter, activityLogger("Viewed subcategory by ID"), findById);

// Admin-only routes (require authentication and admin role)
router.post("/", apiLimiter, protect, authorize('admin'), activityLogger("Created new subcategory"), save);
router.put("/:id", apiLimiter, protect, authorize('admin'), activityLogger("Updated subcategory"), update);
router.delete("/:id", apiLimiter, protect, authorize('admin'), activityLogger("Deleted subcategory"), deleteById);

module.exports = router;
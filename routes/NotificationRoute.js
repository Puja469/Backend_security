const express = require("express");
const router = express.Router();
const { getNotifications, markNotificationsAsRead } = require("../controller/NotificationController");

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
const activityLogger = require("../middleware/activityLogger");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// Protected routes (require authentication)
router.get("/", apiLimiter, protect, authorize('user', 'admin'), activityLogger("Viewed notifications"), getNotifications);
router.put("/markAsRead", apiLimiter, protect, authorize('user', 'admin'), activityLogger("Marked notifications as read"), markNotificationsAsRead);

module.exports = router;

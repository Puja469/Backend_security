const express = require("express");
const router = express.Router();
const { addComment, getCommentsByItem, replyToComment, deleteComment } = require("../controller/CommentController");

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
const { commentSchema } = require("../validation/securityValidation");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// Public routes (read-only)
router.get("/:itemId", apiLimiter, activityLogger("Viewed comments for item"), getCommentsByItem);

// Protected routes (require authentication)
router.post("/", apiLimiter, protect, validateRequest(commentSchema), activityLogger("Added new comment"), addComment);
router.post("/:commentId/reply", apiLimiter, protect, validateRequest(commentSchema), activityLogger("Replied to comment"), replyToComment);
router.delete("/:commentId", apiLimiter, protect, activityLogger("Deleted comment"), deleteComment);

module.exports = router;

const express = require("express");
const router = express.Router();
const { createOrder, getUserOrders, getSoldItems, updateOrderStatus } = require("../controller/OrderController");

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
const { orderSchema } = require("../validation/securityValidation");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// Protected routes (require authentication)
router.post("/", apiLimiter, protect, validateRequest(orderSchema), activityLogger("Created new order"), createOrder);
router.get("/my-orders/:userId", apiLimiter, protect, activityLogger("Viewed user orders"), getUserOrders);
router.get("/my-sold-items/:userId", apiLimiter, protect, activityLogger("Viewed sold items"), getSoldItems);
router.put("/update-status", apiLimiter, protect, authorize('admin'), activityLogger("Updated order status"), updateOrderStatus);

module.exports = router;

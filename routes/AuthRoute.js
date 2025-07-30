const express = require("express");
const router = express.Router();
const {
    login,
    register,
    logout,
    changeAdminPassword,
    registerUser,
    loginUser,
    verifyOTP,
    logoutAllDevices
} = require("../controller/AuthController");
const {
    authLimiter,
    sanitizeData,
    preventXSS,
    preventHPP,
    detectSuspiciousActivity,
    securityHeaders,
    validateRequest
} = require("../middleware/security");
const { protect, authorize } = require("../middleware/auth");
const activityLogger = require("../middleware/activityLogger");
const { userLoginSchema, adminRegistrationSchema } = require("../validation/securityValidation");

// Apply security middleware to all routes
router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);

// User authentication routes with 2FA
router.post("/register-user", authLimiter, activityLogger("User registration attempt"), registerUser);
router.post("/login-user", authLimiter, activityLogger("User login attempt"), loginUser);
router.post("/verify-otp", authLimiter, activityLogger("OTP verification attempt"), verifyOTP);

// Admin-only auth routes with rate limiting and validation
router.post("/login", authLimiter, validateRequest(userLoginSchema), activityLogger("Admin login attempt"), login);
router.post("/register", authLimiter, validateRequest(adminRegistrationSchema), activityLogger("Admin registration attempt"), register);
router.post("/change-password", authLimiter, protect, activityLogger("Admin password change attempt"), changeAdminPassword);

// Logout routes
router.post("/logout", protect, activityLogger("Logout"), logout);
router.post("/logout-all", protect, activityLogger("Logout from all devices"), logoutAllDevices);

module.exports = router;
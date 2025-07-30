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


router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);




router.post("/login", authLimiter, validateRequest(userLoginSchema), activityLogger("Admin login attempt"), login);
router.post("/register", authLimiter, validateRequest(adminRegistrationSchema), activityLogger("Admin registration attempt"), register);
router.post("/change-password", authLimiter, protect, activityLogger("Admin password change attempt"), changeAdminPassword);


router.post("/logout", protect, activityLogger("Logout"), logout);
router.post("/logout-all", protect, activityLogger("Logout from all devices"), logoutAllDevices);

module.exports = router;
const express = require("express");
const router = express.Router();
const {
  findAll,
  save,
  findById,
  getProfile,
  deleteById,
  update,
  login,
  simpleLogin,
  verifyLoginOTP,
  sendVerificationOTP,
  verifyEmail,
  sendPasswordResetOTP,
  resetPassword,
  changePassword
} = require("../controller/UserController");

const { UserValidation, EmailVerificationValidation, SendOTPValidation } = require("../validation/UserValidation");
const upload = require("../middleware/upload");
const {
  apiLimiter,
  authLimiter,
  uploadLimiter,
  sanitizeData,
  preventXSS,
  preventHPP,
  detectSuspiciousActivity,
  securityHeaders
} = require("../middleware/security");
const { validatePasswordMiddleware } = require("../middleware/passwordPolicy");
const { protect, authorize } = require("../middleware/auth");
const { validateCSRFTokenMiddleware } = require("../middleware/csrf");
const activityLogger = require("../middleware/activityLogger");


router.use(sanitizeData);
router.use(preventXSS);
router.use(preventHPP);
router.use(detectSuspiciousActivity);
router.use(securityHeaders);


router.get("/", activityLogger("Viewed all users"), findAll);
router.get("/findAll", protect, authorize('admin'), activityLogger("Viewed all users"), findAll);
router.get("/profile", protect, activityLogger("Viewed own profile"), getProfile);
router.get("/:id", protect, activityLogger("Viewed user by ID"), findById);
router.delete("/:id", protect, authorize('admin'), validateCSRFTokenMiddleware, activityLogger("Deleted user by ID"), deleteById);
router.put("/:id", protect, uploadLimiter, upload, validateCSRFTokenMiddleware, activityLogger("Updated user profile"), update);


router.post("/", apiLimiter, validateCSRFTokenMiddleware, UserValidation, validatePasswordMiddleware, save);

// Auth & verification routes with strict rate limiting
router.post("/sign", authLimiter, login); // 2FA login (requires OTP)
router.post("/simple-login", authLimiter, simpleLogin); // Simple login (no 2FA) - for testing
router.post("/verify-login-otp", authLimiter, verifyLoginOTP);
router.post("/send-otp", authLimiter, SendOTPValidation, sendVerificationOTP);
router.post("/verify-email", authLimiter, EmailVerificationValidation, verifyEmail);
router.post("/forgot-password", authLimiter, SendOTPValidation, sendPasswordResetOTP);
router.post("/reset-password", authLimiter, validateCSRFTokenMiddleware, validatePasswordMiddleware, resetPassword);

// Password change with protection
router.post("/change-password", apiLimiter, protect, validateCSRFTokenMiddleware, validatePasswordMiddleware, changePassword);

module.exports = router;

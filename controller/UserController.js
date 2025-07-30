// 📁 controller/UserController.js (Enhanced with Comprehensive Security Features)
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../model/User");
const SECRET_KEY = process.env.JWT_SECRET;
const otpGenerator = require("otp-generator");
const sendEmail = require("../utils/emailService");
const asyncHandler = require("../middleware/async");
const ActivityLog = require("../model/ActivityLog");
const { validatePassword, getPasswordStrength } = require("../middleware/passwordPolicy");

const logActivity = async (userId, action, ip, userAgent = null, resource = null, method = null, statusCode = null, severity = 'low', metadata = {}) => {
  try {
    if (userId) {
      await ActivityLog.create({
        userId,
        action,
        ipAddress: ip,
        userAgent,
        resource,
        method,
        statusCode,
        severity,
        metadata
      });
    }
  } catch (err) {
    console.error("Activity log failed:", err.message);
  }
};

const findAll = asyncHandler(async (req, res) => {
  const users = await User.find().select('-password -otp -otp_expiry -passwordHistory');
  await logActivity(req.user._id, "admin_action", req.ip, req.get('User-Agent'), '/api/user', 'GET', 200, 'low', { action: 'viewed_all_users' });
  res.status(200).json({
    status: 'success',
    data: users
  });
});

const save = asyncHandler(async (req, res) => {
  const { fname, city, phone, email, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    await logActivity(null, "registration_failed", req.ip, req.get('User-Agent'), '/api/user', 'POST', 409, 'medium', { reason: 'email_already_exists', email });
    return res.status(409).json({
      status: 'error',
      message: "Email is already registered"
    });
  }

  // Enhanced password validation
  const passwordValidation = validatePassword(password, { fname, email, phone, city });
  if (!passwordValidation.isValid) {
    await logActivity(null, "registration_failed", req.ip, req.get('User-Agent'), '/api/user', 'POST', 400, 'medium', { reason: 'password_validation_failed' });
    return res.status(400).json({
      status: 'error',
      message: "Password validation failed",
      errors: passwordValidation.errors
    });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
    digits: true
  });
  const hashedOtp = await bcrypt.hash(otp, 10);
  const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

  const user = new User({
    fname,
    email,
    phone,
    city,
    password: hashedPassword,
    otp: hashedOtp,
    otp_expiry: otpExpiry,
    passwordChangedAt: new Date(),
    passwordHistory: []
  });

  const savedUser = await user.save();

  // Send verification email with proper error handling
  try {
    await sendEmail(email, "Email Verification OTP", `Hello ${fname},\n\nYour OTP is: ${otp}`);
    console.log(`✅ Verification email sent successfully to ${email}`);
  } catch (emailError) {
    console.error(`❌ Failed to send verification email to ${email}:`, emailError.message);
    // Don't fail the registration if email fails, but log it
    await logActivity(savedUser._id, "registration_failed", req.ip, req.get('User-Agent'), '/api/user', 'POST', 201, 'medium', { reason: 'email_send_failed', emailError: emailError.message });
  }

  await logActivity(savedUser._id, "Registered", req.ip, req.get('User-Agent'), '/api/user', 'POST', 201, 'low');

  // Don't send sensitive data in response
  const userResponse = {
    id: savedUser._id,
    fname: savedUser.fname,
    email: savedUser.email,
    phone: savedUser.phone,
    city: savedUser.city,
    createdAt: savedUser.createdAt
  };

  res.status(201).json({
    status: 'success',
    message: "User registered successfully. Please verify your email.",
    data: userResponse
  });
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find user with all necessary fields
  const user = await User.findOne({ email }).select("+password +otp +otp_expiry +loginAttempts +lockUntil +isLocked +passwordChangedAt");

  if (!user) {
    await logActivity(null, "login_failed", req.ip, req.get('User-Agent'), '/api/user/sign', 'POST', 404, 'medium', { reason: 'user_not_found', email });
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  // Check if account is locked
  if (user.isAccountLocked) {
    const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
    await logActivity(user._id, "account_locked", req.ip, req.get('User-Agent'), '/api/user/sign', 'POST', 423, 'high', { lockTimeRemaining });
    return res.status(423).json({
      status: 'error',
      message: `Account is locked due to multiple failed login attempts. Try again in ${lockTimeRemaining} minutes.`
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    // Increment login attempts
    await user.incLoginAttempts();

    await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/user/sign', 'POST', 401, 'medium', { reason: 'invalid_password' });
    return res.status(401).json({
      status: 'error',
      message: "Invalid password"
    });
  }

  // Reset login attempts on successful password verification
  await user.resetLoginAttempts();

  // Check password expiry
  if (Date.now() - user.passwordChangedAt.getTime() > 90 * 24 * 60 * 60 * 1000) {
    await logActivity(user._id, "password_expired", req.ip, req.get('User-Agent'), '/api/user/sign', 'POST', 403, 'medium');
    return res.status(403).json({
      status: 'error',
      message: "Your password has expired. Please reset to continue."
    });
  }

  // Generate OTP for 2FA
  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
    digits: true
  });
  const hashedOtp = await bcrypt.hash(otp, 10);
  const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

  // Save OTP to user
  user.otp = hashedOtp;
  user.otp_expiry = otpExpiry;
  await user.save();

  // Send OTP email with proper error handling
  try {
    await sendEmail(email, "Login Verification OTP", `Hello ${user.fname},\n\nYour login verification OTP is: ${otp}\n\nThis OTP will expire in 5 minutes.`);
    console.log(`✅ Login OTP email sent successfully to ${email}`);
  } catch (emailError) {
    console.error(`❌ Failed to send login OTP email to ${email}:`, emailError.message);
    // Log the email failure but don't fail the login process
    await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/user/sign', 'POST', 200, 'medium', { reason: 'otp_email_failed', emailError: emailError.message });
  }

  await logActivity(user._id, "login", req.ip, req.get('User-Agent'), '/api/user/sign', 'POST', 200, 'low', { step: 'otp_sent' });

  res.status(200).json({
    status: 'success',
    message: "OTP sent to your email. Please verify to complete login.",
    data: {
      userId: user._id,
      email: user.email
    }
  });
});

const simpleLogin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find user with all necessary fields
  const user = await User.findOne({ email }).select("+password +loginAttempts +lockUntil +isLocked +passwordChangedAt");

  if (!user) {
    await logActivity(null, "login_failed", req.ip, req.get('User-Agent'), '/api/user/simple-login', 'POST', 404, 'medium', { reason: 'user_not_found', email });
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  // Check if account is locked
  if (user.isAccountLocked) {
    const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
    await logActivity(user._id, "account_locked", req.ip, req.get('User-Agent'), '/api/user/simple-login', 'POST', 423, 'high', { lockTimeRemaining });
    return res.status(423).json({
      status: 'error',
      message: `Account is locked due to multiple failed login attempts. Try again in ${lockTimeRemaining} minutes.`
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    // Increment login attempts
    await user.incLoginAttempts();

    await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/user/simple-login', 'POST', 401, 'medium', { reason: 'invalid_password' });
    return res.status(401).json({
      status: 'error',
      message: "Invalid password"
    });
  }

  // Reset login attempts on successful password verification
  await user.resetLoginAttempts();

  // Check password expiry
  if (Date.now() - user.passwordChangedAt.getTime() > 90 * 24 * 60 * 60 * 1000) {
    await logActivity(user._id, "password_expired", req.ip, req.get('User-Agent'), '/api/user/simple-login', 'POST', 403, 'medium');
    return res.status(403).json({
      status: 'error',
      message: "Your password has expired. Please reset to continue."
    });
  }

  // Update last login info
  user.lastLoginAt = new Date();
  user.lastLoginIp = req.ip;
  await user.save();

  // Create JWT token with session version
  const token = jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: 'user',
      sessionVersion: user.sessionVersion
    },
    SECRET_KEY,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '3d',
      issuer: 'thriftstore-api',
      audience: 'thriftstore-client'
    }
  );

  // Set secure HTTP-only cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: (process.env.JWT_COOKIE_EXPIRES_IN || 72) * 60 * 60 * 1000, // 3 days
    path: '/'
  });

  await logActivity(user._id, "login", req.ip, req.get('User-Agent'), '/api/user/simple-login', 'POST', 200, 'low', { method: 'simple_login' });

  res.status(200).json({
    status: 'success',
    message: "Login successful",
    data: {
      id: user._id,
      fname: user.fname,
      email: user.email,
      role: 'user',
      token: token
    }
  });
});

const verifyLoginOTP = asyncHandler(async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.status(400).json({
      status: 'error',
      message: "User ID and OTP are required"
    });
  }

  const user = await User.findById(userId).select('+otp +otp_expiry');

  if (!user) {
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  // Check if OTP exists and is not expired
  if (!user.otp || !user.otp_expiry || user.otp_expiry < Date.now()) {
    await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/user/verify-login-otp', 'POST', 400, 'medium', { reason: 'otp_expired_or_invalid' });
    return res.status(400).json({
      status: 'error',
      message: "OTP has expired or is invalid"
    });
  }

  // Verify OTP
  const isOTPValid = await bcrypt.compare(otp, user.otp);
  if (!isOTPValid) {
    await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/user/verify-login-otp', 'POST', 400, 'medium', { reason: 'invalid_otp' });
    return res.status(400).json({
      status: 'error',
      message: "Invalid OTP"
    });
  }

  // Clear OTP after successful verification
  user.otp = undefined;
  user.otp_expiry = undefined;
  user.lastLoginAt = new Date();
  user.lastLoginIp = req.ip;
  await user.save();

  // Create JWT token with session version
  const token = jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: 'user',
      sessionVersion: user.sessionVersion
    },
    SECRET_KEY,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '3d',
      issuer: 'thriftstore-api',
      audience: 'thriftstore-client'
    }
  );

  // Set secure HTTP-only cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: (process.env.JWT_COOKIE_EXPIRES_IN || 72) * 60 * 60 * 1000, // 3 days
    path: '/'
  });

  await logActivity(user._id, "login", req.ip, req.get('User-Agent'), '/api/user/verify-login-otp', 'POST', 200, 'low', { step: 'login_completed' });

  res.status(200).json({
    status: 'success',
    message: "Login successful",
    data: {
      id: user._id,
      fname: user.fname,
      email: user.email,
      role: 'user',
      token: token
    }
  });
});

const sendVerificationOTP = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    await logActivity(null, "otp_request_failed", req.ip, req.get('User-Agent'), '/api/user/send-otp', 'POST', 400, 'medium', { reason: 'user_not_found', email });
    return res.status(400).json({
      status: 'error',
      message: "User not found"
    });
  }

  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
    digits: true
  });
  user.otp = await bcrypt.hash(otp, 10);
  user.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
  await user.save();

  await sendEmail(email, "Email Verification OTP", `Hello ${user.fname},\n\nYour OTP is: ${otp}`);

  await logActivity(user._id, "otp_sent", req.ip, req.get('User-Agent'), '/api/user/send-otp', 'POST', 200, 'low', { type: 'email_verification' });

  res.status(200).json({
    status: 'success',
    message: "OTP sent for email verification"
  });
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });

  if (!user || !user.otp || !user.otp_expiry) {
    await logActivity(null, "email_verification_failed", req.ip, req.get('User-Agent'), '/api/user/verify-email', 'POST', 400, 'medium', { reason: 'invalid_or_expired_otp', email });
    return res.status(400).json({
      status: 'error',
      message: "Invalid or expired OTP"
    });
  }

  const isOtpValid = await bcrypt.compare(otp, user.otp);
  if (!isOtpValid) {
    await logActivity(user._id, "email_verification_failed", req.ip, req.get('User-Agent'), '/api/user/verify-email', 'POST', 400, 'medium', { reason: 'invalid_otp' });
    return res.status(400).json({
      status: 'error',
      message: "Invalid OTP"
    });
  }

  user.is_verified = true;
  user.otp = null;
  user.otp_expiry = null;
  await user.save();

  await logActivity(user._id, "Verified Email", req.ip, req.get('User-Agent'), '/api/user/verify-email', 'POST', 200, 'low');

  res.status(200).json({
    status: 'success',
    message: "Email verified successfully"
  });
});

const sendPasswordResetOTP = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    await logActivity(null, "password_reset_request_failed", req.ip, req.get('User-Agent'), '/api/user/forgot-password', 'POST', 400, 'medium', { reason: 'user_not_found', email });
    return res.status(400).json({
      status: 'error',
      message: "User not found"
    });
  }

  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
    digits: true
  });
  user.otp = await bcrypt.hash(otp, 10);
  user.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
  await user.save();

  await sendEmail(email, "Password Reset OTP", `Hello ${user.fname},\n\nYour password reset OTP is: ${otp}\n\nThis OTP will expire in 10 minutes.`);

  await logActivity(user._id, "otp_sent", req.ip, req.get('User-Agent'), '/api/user/forgot-password', 'POST', 200, 'low', { type: 'password_reset' });

  res.status(200).json({
    status: 'success',
    message: "OTP sent for password reset"
  });
});

const resetPassword = asyncHandler(async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const user = await User.findOne({ email }).select("+otp +otp_expiry +passwordHistory +passwordChangedAt");

  if (!user || !user.otp || !user.otp_expiry) {
    await logActivity(null, "password_reset_failed", req.ip, req.get('User-Agent'), '/api/user/reset-password', 'POST', 400, 'medium', { reason: 'invalid_request', email });
    return res.status(400).json({
      status: 'error',
      message: "Invalid request"
    });
  }

  const isOtpValid = await bcrypt.compare(otp, user.otp);
  if (!isOtpValid) {
    await logActivity(user._id, "password_reset_failed", req.ip, req.get('User-Agent'), '/api/user/reset-password', 'POST', 400, 'medium', { reason: 'invalid_otp' });
    return res.status(400).json({
      status: 'error',
      message: "Invalid OTP"
    });
  }

  if (Date.now() > user.otp_expiry.getTime()) {
    await logActivity(user._id, "password_reset_failed", req.ip, req.get('User-Agent'), '/api/user/reset-password', 'POST', 400, 'medium', { reason: 'otp_expired' });
    return res.status(400).json({
      status: 'error',
      message: "OTP has expired"
    });
  }

  // Enhanced password validation
  const passwordValidation = validatePassword(newPassword, { email });
  if (!passwordValidation.isValid) {
    await logActivity(user._id, "password_reset_failed", req.ip, req.get('User-Agent'), '/api/user/reset-password', 'POST', 400, 'medium', { reason: 'password_validation_failed' });
    return res.status(400).json({
      status: 'error',
      message: "Password validation failed",
      errors: passwordValidation.errors
    });
  }

  // Check password history
  for (const oldPasswordHash of user.passwordHistory || []) {
    const isMatch = await bcrypt.compare(newPassword, oldPasswordHash);
    if (isMatch) {
      await logActivity(user._id, "password_reset_failed", req.ip, req.get('User-Agent'), '/api/user/reset-password', 'POST', 400, 'medium', { reason: 'password_reused' });
      return res.status(400).json({
        status: 'error',
        message: "You can't reuse any of your last 5 passwords."
      });
    }
  }

  user.passwordHistory.unshift(user.password);
  user.passwordHistory = user.passwordHistory.slice(0, 5);
  user.password = await bcrypt.hash(newPassword, 12);
  user.passwordChangedAt = new Date();
  user.otp = null;
  user.otp_expiry = null;
  await user.save();

  await logActivity(user._id, "Reset Password", req.ip, req.get('User-Agent'), '/api/user/reset-password', 'POST', 200, 'high');

  res.status(200).json({
    status: 'success',
    message: "Password reset successfully"
  });
});

const findById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).select('-password -otp -otp_expiry -passwordHistory');

  if (!user) {
    await logActivity(req.user._id, "user_view_failed", req.ip, req.get('User-Agent'), `/api/user/${req.params.id}`, 'GET', 404, 'medium', { reason: 'user_not_found' });
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  await logActivity(req.user._id, "Viewed user by ID", req.ip, req.get('User-Agent'), `/api/user/${req.params.id}`, 'GET', 200, 'low');

  res.status(200).json({
    status: 'success',
    data: user
  });
});

const getProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select('-password -otp -otp_expiry -passwordHistory');

  if (!user) {
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  await logActivity(req.user._id, "Viewed own profile", req.ip, req.get('User-Agent'), '/api/user/profile', 'GET', 200, 'low');

  res.status(200).json({
    status: 'success',
    data: user
  });
});

const deleteById = asyncHandler(async (req, res) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    await logActivity(req.user._id, "user_deletion_failed", req.ip, req.get('User-Agent'), `/api/user/${req.params.id}`, 'DELETE', 404, 'medium', { reason: 'user_not_found' });
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  await logActivity(req.user._id, "Deleted user by ID", req.ip, req.get('User-Agent'), `/api/user/${req.params.id}`, 'DELETE', 200, 'high', { deletedUserId: user._id });

  res.status(200).json({
    status: 'success',
    message: "User deleted successfully"
  });
});

const update = asyncHandler(async (req, res) => {
  const { fname, city } = req.body;
  let image = req.file ? `/uploads/${req.file.filename}` : undefined;

  const updateFields = { fname, city };
  if (image) updateFields.image = image;

  const user = await User.findByIdAndUpdate(req.params.id, updateFields, { new: true }).select('-password -otp -otp_expiry -passwordHistory');

  if (!user) {
    await logActivity(req.user._id, "profile_update_failed", req.ip, req.get('User-Agent'), `/api/user/${req.params.id}`, 'PUT', 404, 'medium', { reason: 'user_not_found' });
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  await logActivity(req.user._id, "Updated user profile", req.ip, req.get('User-Agent'), `/api/user/${req.params.id}`, 'PUT', 202, 'low');

  res.status(202).json({
    status: 'success',
    message: "Profile updated successfully",
    data: user
  });
});

const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user._id).select("+password +passwordHistory +passwordChangedAt");

  if (!user) {
    return res.status(404).json({
      status: 'error',
      message: "User not found"
    });
  }

  const isMatch = await bcrypt.compare(currentPassword, user.password);
  if (!isMatch) {
    await logActivity(req.user._id, "password_change_failed", req.ip, req.get('User-Agent'), '/api/user/change-password', 'POST', 401, 'medium', { reason: 'current_password_incorrect' });
    return res.status(401).json({
      status: 'error',
      message: "Current password is incorrect"
    });
  }

  // Enhanced password validation
  const passwordValidation = validatePassword(newPassword, { email: user.email });
  if (!passwordValidation.isValid) {
    await logActivity(req.user._id, "password_change_failed", req.ip, req.get('User-Agent'), '/api/user/change-password', 'POST', 400, 'medium', { reason: 'password_validation_failed' });
    return res.status(400).json({
      status: 'error',
      message: "Password validation failed",
      errors: passwordValidation.errors
    });
  }

  // Check password history
  for (const oldPasswordHash of user.passwordHistory || []) {
    const isMatch = await bcrypt.compare(newPassword, oldPasswordHash);
    if (isMatch) {
      await logActivity(req.user._id, "password_change_failed", req.ip, req.get('User-Agent'), '/api/user/change-password', 'POST', 400, 'medium', { reason: 'password_reused' });
      return res.status(400).json({
        status: 'error',
        message: "You can't reuse any of your last 5 passwords."
      });
    }
  }

  user.passwordHistory.unshift(user.password);
  user.passwordHistory = user.passwordHistory.slice(0, 5);
  user.password = await bcrypt.hash(newPassword, 12);
  user.passwordChangedAt = new Date();

  await user.save();
  await logActivity(req.user._id, "Changed Password", req.ip, req.get('User-Agent'), '/api/user/change-password', 'POST', 200, 'high');

  res.status(200).json({
    status: 'success',
    message: "Password changed successfully"
  });
});

module.exports = {
  findAll,
  save,
  login,
  simpleLogin,
  verifyLoginOTP,
  sendVerificationOTP,
  verifyEmail,
  sendPasswordResetOTP,
  resetPassword,
  findById,
  getProfile,
  deleteById,
  update,
  changePassword,
};

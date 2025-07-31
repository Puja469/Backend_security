const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Credential = require("../model/Credential");
const User = require("../model/User");
const otpGenerator = require("otp-generator");
const { sendEmail, createEmailVerificationTemplate, createPasswordResetTemplate, createLoginVerificationTemplate } = require("../utils/emailService");
const ActivityLog = require("../model/ActivityLog");

const logActivity = async (userId, action, ip, userAgent = null, resource = null, method = null, statusCode = null, severity = 'low', metadata = {}) => {
    try {
        await ActivityLog.create({
            userId: userId || null, // Allow null for anonymous activities
            action,
            ipAddress: ip,
            userAgent,
            resource,
            method,
            statusCode,
            severity,
            metadata
        });
    } catch (err) {
        console.error("Activity log failed:", err.message);
    }
};

// Register regular user
const registerUser = async (req, res) => {
    try {
        const { fname, email, phone, city, password } = req.body;

        if (!fname || !email || !phone || !city || !password) {
            return res.status(400).json({
                status: 'error',
                message: "All fields are required"
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                status: 'error',
                message: "User with this email already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate OTP for email verification
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

        // Send verification email
        const emailTemplate = createEmailVerificationTemplate(fname, otp);
        await sendEmail(email, "🛍️ Welcome to ThriftStore - Verify Your Account", emailTemplate.text, emailTemplate.html);
        await logActivity(savedUser._id, "Registered", req.ip, req.get('User-Agent'), '/api/auth/register', 'POST', 201);

        // Don't send password in response
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
    } catch (error) {
        console.error('User registration error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error registering user",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Register admin (existing function)
const register = async (req, res) => {
    try {
        const { fname, email, password, role } = req.body;

        if (!fname || !email || !password) {
            return res.status(400).json({
                status: 'error',
                message: "Name, email and password are required"
            });
        }

        // Check if admin already exists
        const existingAdmin = await Credential.findOne({ email });
        if (existingAdmin) {
            return res.status(409).json({
                status: 'error',
                message: "Admin with this email already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        const admin = new Credential({
            fname,
            email,
            password: hashedPassword,
            role: role || 'admin'
        });

        const savedAdmin = await admin.save();

        // Log admin registration
        await logActivity(savedAdmin._id, "admin_action", req.ip, req.get('User-Agent'), '/api/auth/register-admin', 'POST', 201, 'high', { action: 'admin_registration' });

        res.status(201).json({
            status: 'success',
            message: "Admin registered successfully",
            data: {
                id: savedAdmin._id,
                fname: savedAdmin.fname,
                email: savedAdmin.email,
                role: savedAdmin.role
            }
        });
    } catch (error) {
        console.error('Admin registration error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error registering admin",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Enhanced user login with 2FA and account lockout
const loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                message: "Email and password are required"
            });
        }

        // Find user and include password for comparison
        const user = await User.findOne({ email }).select('+password +otp +otp_expiry +loginAttempts +lockUntil +isLocked');

        if (!user) {
            await logActivity(null, "login_failed", req.ip, req.get('User-Agent'), '/api/auth/login', 'POST', 401, 'medium', { reason: 'user_not_found', email });
            return res.status(401).json({
                status: 'error',
                message: "Invalid email or password"
            });
        }

        // Check if account is locked
        if (user.isAccountLocked) {
            const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
            await logActivity(user._id, "account_locked", req.ip, req.get('User-Agent'), '/api/auth/login', 'POST', 423, 'high', { lockTimeRemaining });
            return res.status(423).json({
                status: 'error',
                message: `Account is locked due to multiple failed login attempts. Try again in ${lockTimeRemaining} minutes.`
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            // Increment login attempts
            await user.incLoginAttempts();

            await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/auth/login', 'POST', 401, 'medium', { reason: 'invalid_password' });

            return res.status(401).json({
                status: 'error',
                message: "Invalid email or password"
            });
        }

        // Reset login attempts on successful password verification
        await user.resetLoginAttempts();

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

        // Send OTP email
        const emailTemplate = createLoginVerificationTemplate(user.fname, otp);
        await sendEmail(user.email, "🔐 Complete Your ThriftStore Login", emailTemplate.text, emailTemplate.html);

        await logActivity(user._id, "login", req.ip, req.get('User-Agent'), '/api/auth/login', 'POST', 200, 'low', { step: 'otp_sent' });

        res.status(200).json({
            status: 'success',
            message: "OTP sent to your email. Please verify to complete login.",
            data: {
                userId: user._id,
                email: user.email
            }
        });
    } catch (error) {
        console.error('User login error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error during login",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Verify OTP and complete login
const verifyOTP = async (req, res) => {
    const { userId, otp } = req.body;

    try {
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
            await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/auth/verify-otp', 'POST', 400, 'medium', { reason: 'otp_expired_or_invalid' });
            return res.status(400).json({
                status: 'error',
                message: "OTP has expired or is invalid"
            });
        }

        // Verify OTP
        const isOTPValid = await bcrypt.compare(otp, user.otp);
        if (!isOTPValid) {
            await logActivity(user._id, "login_failed", req.ip, req.get('User-Agent'), '/api/auth/verify-otp', 'POST', 400, 'medium', { reason: 'invalid_otp' });
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
            process.env.JWT_SECRET,
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

        await logActivity(user._id, "login", req.ip, req.get('User-Agent'), '/api/auth/verify-otp', 'POST', 200, 'low', { step: 'login_completed' });

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
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error verifying OTP",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Admin login (existing function)
const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                message: "Email and password are required"
            });
        }

        const admin = await Credential.findOne({ email });
        if (!admin) {
            await logActivity(null, "login_failed", req.ip, req.get('User-Agent'), '/api/auth/login-admin', 'POST', 401, 'medium', { reason: 'admin_not_found', email });
            return res.status(401).json({
                status: 'error',
                message: "Invalid email or password"
            });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            await logActivity(null, "login_failed", req.ip, req.get('User-Agent'), '/api/auth/login-admin', 'POST', 401, 'medium', { reason: 'invalid_password', email });
            return res.status(401).json({
                status: 'error',
                message: "Invalid email or password"
            });
        }


        const token = jwt.sign(
            {
                id: admin._id,
                email: admin.email,
                role: admin.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRES_IN || '1h',
                issuer: 'thriftstore-api',
                audience: 'thriftstore-client'
            }
        );


        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: (process.env.JWT_COOKIE_EXPIRES_IN || 1) * 60 * 60 * 1000,
            path: '/'
        });

        await logActivity(admin._id, "login", req.ip, req.get('User-Agent'), '/api/auth/login-admin', 'POST', 200, 'low', { role: 'admin' });

        res.status(200).json({
            status: 'success',
            message: "Admin login successful",
            data: {
                id: admin._id,
                fname: admin.fname,
                email: admin.email,
                role: admin.role,
                token: token
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error logging in",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};


const logout = async (req, res) => {
    try {

        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        if (req.user) {
            await logActivity(req.user._id, "logout", req.ip, req.get('User-Agent'), '/api/auth/logout', 'POST', 200);
        }

        res.status(200).json({
            status: 'success',
            message: "Logout successful"
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error during logout",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};


const logoutAllDevices = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                status: 'error',
                message: "User not authenticated"
            });
        }


        await req.user.invalidateSessions();


        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        await logActivity(req.user._id, "logout", req.ip, req.get('User-Agent'), '/api/auth/logout-all', 'POST', 200, 'medium', { action: 'logout_all_devices' });

        res.status(200).json({
            status: 'success',
            message: "Logged out from all devices successfully"
        });
    } catch (error) {
        console.error('Logout all devices error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error during logout",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Change admin password
const changeAdminPassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                status: 'error',
                message: "Current password and new password are required"
            });
        }

        const admin = await Credential.findById(req.user._id);
        if (!admin) {
            return res.status(404).json({
                status: 'error',
                message: "Admin not found"
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, admin.password);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({
                status: 'error',
                message: "Current password is incorrect"
            });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 12);

        // Update password
        admin.password = hashedNewPassword;
        await admin.save();

        await logActivity(admin._id, "password_changed", req.ip, req.get('User-Agent'), '/api/auth/change-password', 'POST', 200, 'high', { role: 'admin' });

        res.status(200).json({
            status: 'success',
            message: "Password changed successfully"
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            status: 'error',
            message: "Error changing password",
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

module.exports = {
    registerUser,
    register,
    loginUser,
    verifyOTP,
    login,
    logout,
    logoutAllDevices,
    changeAdminPassword
};
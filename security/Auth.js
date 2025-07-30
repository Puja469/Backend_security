const jwt = require("jsonwebtoken");
const User = require("../model/User");

// Use environment variable for JWT secret
const SECRET_KEY = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

function authenticateToken(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            status: 'error',
            message: "Access denied: No token provided"
        });
    }

    try {
        const verified = jwt.verify(token, SECRET_KEY, {
            issuer: 'thriftstore-api',
            audience: 'thriftstore-client'
        });

        req.user = verified;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                status: 'error',
                message: "Invalid token"
            });
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                status: 'error',
                message: "Token expired. Please log in again"
            });
        }

        return res.status(400).json({
            status: 'error',
            message: "Invalid token"
        });
    }
}

function authorizeRole(role) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                status: 'error',
                message: "User not authenticated"
            });
        }

        if (req.user.role !== role) {
            return res.status(403).json({
                status: 'error',
                message: "Access Denied: Insufficient Permissions"
            });
        }

        next();
    };
}

// Enhanced token verification with user lookup
async function authenticateTokenWithUser(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            status: 'error',
            message: "Access denied: No token provided"
        });
    }

    try {
        const verified = jwt.verify(token, SECRET_KEY, {
            issuer: 'thriftstore-api',
            audience: 'thriftstore-client'
        });

        // Fetch user from database to ensure they still exist and are active
        const user = await User.findById(verified.id).select("-password");

        if (!user) {
            return res.status(401).json({
                status: 'error',
                message: "User not found or token invalid"
            });
        }

        if (!user.isActive) {
            return res.status(401).json({
                status: 'error',
                message: "User account is deactivated"
            });
        }

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                status: 'error',
                message: "Invalid token"
            });
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                status: 'error',
                message: "Token expired. Please log in again"
            });
        }

        return res.status(400).json({
            status: 'error',
            message: "Invalid token"
        });
    }
}

module.exports = {
    authenticateToken,
    authorizeRole,
    authenticateTokenWithUser
};
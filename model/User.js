const mongoose = require("mongoose");
const { safeEncrypt, safeDecrypt } = require("../utils/encryption");

const userSchema = new mongoose.Schema({
    fname: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,             // prevent duplicate emails
        trim: true,
        set: function (value) {
            // Convert to lowercase before encryption
            const lowerValue = value.toLowerCase();
            return safeEncrypt(lowerValue, process.env.DATA_ENCRYPTION_KEY);
        },
        get: function (value) {
            return safeDecrypt(value, process.env.DATA_ENCRYPTION_KEY);
        }
    },
    phone: {
        type: String,
        required: true,
        trim: true,
        set: function (value) {
            return safeEncrypt(value, process.env.DATA_ENCRYPTION_KEY);
        },
        get: function (value) {
            return safeDecrypt(value, process.env.DATA_ENCRYPTION_KEY);
        }
    },
    city: {
        type: String,
        required: true,
        trim: true,
        set: function (value) {
            return safeEncrypt(value, process.env.DATA_ENCRYPTION_KEY);
        },
        get: function (value) {
            return safeDecrypt(value, process.env.DATA_ENCRYPTION_KEY);
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 8              // enforce stronger passwords
    },
    // track when password was last changed
    passwordChangedAt: {
        type: Date,
        default: Date.now
    },
    // store hashes of previous passwords to prevent reuse
    passwordHistory: {
        type: [String],
        default: []
    },
    image: {
        type: String,
        default: null
    },
    is_verified: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    },
    otp: {
        type: String,
        select: false             // hide from queries unless explicitly selected
    },
    otp_expiry: {
        type: Date,
        select: false
    },
    // Account lockout fields
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date,
        default: null
    },
    isLocked: {
        type: Boolean,
        default: false
    },

    sessionVersion: {
        type: Number,
        default: 1
    },

    lastLoginAt: {
        type: Date,
        default: null
    },
    lastLoginIp: {
        type: String,
        default: null
    },
    // Google OAuth fields
    googleId: {
        type: String,
        default: null
    },
    isGoogleUser: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true,            // adds createdAt and updatedAt fields automatically
    toJSON: { getters: true },   // enable getters when converting to JSON
    toObject: { getters: true }  // enable getters when converting to object
});

// Virtual for checking if account is locked
userSchema.virtual('isAccountLocked').get(function () {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function () {
    // If we have a previous lock that has expired, restart at 1
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $unset: { lockUntil: 1 },
            $set: { loginAttempts: 1 }
        });
    }

    const updates = { $inc: { loginAttempts: 1 } };

    // Lock account after 5 failed attempts for 15 minutes
    if (this.loginAttempts + 1 >= 5 && !this.isAccountLocked) {
        updates.$set = { lockUntil: Date.now() + 15 * 60 * 1000 }; // 15 minutes
    }

    return this.updateOne(updates);
};


userSchema.methods.resetLoginAttempts = function () {
    return this.updateOne({
        $unset: { loginAttempts: 1, lockUntil: 1 },
        $set: { isLocked: false }
    });
};


userSchema.methods.invalidateSessions = function () {
    return this.updateOne({
        $inc: { sessionVersion: 1 }
    });
};

const User = mongoose.model("Users", userSchema);
module.exports = User;

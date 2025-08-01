const mongoose = require("mongoose");

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
            // Convert to lowercase
            return value.toLowerCase();
        }
    },
    phone: {
        type: String,
        required: true,
        trim: true
    },
    city: {
        type: String,
        required: true,
        trim: true
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
    },
    // Admin block functionality
    isBlocked: {
        type: Boolean,
        default: false
    },
    blockedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users",
        default: null
    },
    blockedAt: {
        type: Date,
        default: null
    },
    blockReason: {
        type: String,
        default: null
    },
    unblockedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users",
        default: null
    },
    unblockedAt: {
        type: Date,
        default: null
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

// Method to block user
userSchema.methods.blockUser = function (adminId, reason) {
    return this.updateOne({
        $set: {
            isBlocked: true,
            blockedBy: adminId,
            blockedAt: new Date(),
            blockReason: reason,
            isLocked: true // Also lock the account
        },
        $unset: {
            unblockedBy: 1,
            unblockedAt: 1
        }
    });
};

// Method to unblock user
userSchema.methods.unblockUser = function (adminId) {
    return this.updateOne({
        $set: {
            isBlocked: false,
            unblockedBy: adminId,
            unblockedAt: new Date(),
            isLocked: false,
            loginAttempts: 0
        },
        $unset: {
            blockedBy: 1,
            blockedAt: 1,
            blockReason: 1,
            lockUntil: 1
        }
    });
};

const User = mongoose.model("Users", userSchema);
module.exports = User;

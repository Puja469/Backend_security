const mongoose = require("mongoose");

const activityLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Users",
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'login',
      'logout',
      'login_failed',
      'account_locked',
      'password_changed',
      'profile_updated',
      'item_created',
      'item_updated',
      'item_deleted',
      'order_created',
      'order_updated',
      'suspicious_activity',
      'rate_limit_exceeded',
      'file_uploaded',
      'admin_action',
      'security_event',
      'Registered',
      'registration_failed',
      'email_verification_failed',
      'password_reset_failed',
      'otp_sent',
      'otp_request_failed',
      'password_reset_request_failed',
      'email_verification_successful',
      'password_reset_successful',
      'user_view_failed',
      'user_deletion_failed',
      'profile_update_failed',
      'password_change_failed',
      'account_locked',
      'password_expired',
      'otp_expired_or_invalid',
      'invalid_otp',
      'otp_validation_failed'
    ]
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    default: null
  },
  resource: {
    type: String,
    default: null
  },
  method: {
    type: String,
    default: null
  },
  statusCode: {
    type: Number,
    default: null
  },
  metadata: {
    type: Object,
    default: {}
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient querying
activityLogSchema.index({ userId: 1, timestamp: -1 });
activityLogSchema.index({ action: 1, timestamp: -1 });
activityLogSchema.index({ severity: 1, timestamp: -1 });
activityLogSchema.index({ ipAddress: 1, timestamp: -1 });

const ActivityLog = mongoose.model("ActivityLog", activityLogSchema);
module.exports = ActivityLog;

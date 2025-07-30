const express = require("express");
const router = express.Router();
const { protect, authorize } = require("../middleware/auth");
const {
    getSecurityMetrics,
    getSecurityTrends,
    getSuspiciousIPs,
    getSecurityEvents,
    exportSecurityLogs,
    getSystemHealth
} = require("../controller/SecurityController");

// All security routes require authentication and admin role
router.use(protect);
router.use(authorize('admin'));

// Get real-time security metrics
router.get("/metrics", getSecurityMetrics);

// Get security event trends
router.get("/trends", getSecurityTrends);

// Get suspicious IP addresses
router.get("/suspicious-ips", getSuspiciousIPs);

// Get security events with filtering
router.get("/events", getSecurityEvents);

// Export security logs
router.get("/export", exportSecurityLogs);

// Get system health metrics
router.get("/health", getSystemHealth);

module.exports = router; 
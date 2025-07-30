const mongoose = require("mongoose");
const ActivityLog = require("../model/ActivityLog");
const User = require("../model/User");
const asyncHandler = require("../middleware/async");

// Get real-time security metrics
const getSecurityMetrics = asyncHandler(async (req, res) => {
    try {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Failed login attempts in last hour
        const failedLogins = await ActivityLog.countDocuments({
            action: 'login_failed',
            timestamp: { $gte: oneHourAgo }
        });

        // Suspicious activities in last hour
        const suspiciousActivities = await ActivityLog.countDocuments({
            action: { $in: ['suspicious_activity', 'rate_limit_exceeded', 'account_locked'] },
            timestamp: { $gte: oneHourAgo }
        });

        // Rate limit violations in last hour
        const rateLimitViolations = await ActivityLog.countDocuments({
            action: 'rate_limit_exceeded',
            timestamp: { $gte: oneHourAgo }
        });

        // Locked accounts
        const lockedAccounts = await User.countDocuments({
            isLocked: true,
            lockUntil: { $gt: now }
        });

        // Total users
        const totalUsers = await User.countDocuments();

        // Active users (logged in within last 24 hours)
        const activeUsers = await User.countDocuments({
            lastLoginAt: { $gte: oneDayAgo }
        });

        const activeRate = totalUsers > 0 ? ((activeUsers / totalUsers) * 100).toFixed(1) : 0;

        res.status(200).json({
            status: 'success',
            data: {
                failedLoginAttempts: failedLogins,
                suspiciousActivities: suspiciousActivities,
                rateLimitViolations: rateLimitViolations,
                lockedAccounts: lockedAccounts,
                totalUsers: totalUsers,
                activeUsers: activeUsers,
                activeRate: parseFloat(activeRate)
            }
        });
    } catch (error) {
        console.error('Error getting security metrics:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error retrieving security metrics'
        });
    }
});

// Get security event trends
const getSecurityTrends = asyncHandler(async (req, res) => {
    try {
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Get hourly data for the last 24 hours
        const hourlyData = [];
        for (let i = 23; i >= 0; i--) {
            const hourStart = new Date(now.getTime() - i * 60 * 60 * 1000);
            const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000);

            const events = await ActivityLog.countDocuments({
                timestamp: { $gte: hourStart, $lt: hourEnd }
            });

            hourlyData.push({
                hour: hourStart.getHours(),
                events: events
            });
        }

        // Get security event distribution by type
        const eventDistribution = await ActivityLog.aggregate([
            {
                $match: {
                    timestamp: { $gte: oneDayAgo }
                }
            },
            {
                $group: {
                    _id: '$action',
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { count: -1 }
            }
        ]);

        // Get severity distribution
        const severityDistribution = await ActivityLog.aggregate([
            {
                $match: {
                    timestamp: { $gte: oneDayAgo }
                }
            },
            {
                $group: {
                    _id: '$severity',
                    count: { $sum: 1 }
                }
            }
        ]);

        res.status(200).json({
            status: 'success',
            data: {
                hourlyTrends: hourlyData,
                eventDistribution: eventDistribution,
                severityDistribution: severityDistribution
            }
        });
    } catch (error) {
        console.error('Error getting security trends:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error retrieving security trends'
        });
    }
});

// Get suspicious IP addresses
const getSuspiciousIPs = asyncHandler(async (req, res) => {
    try {
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        // Find IPs with multiple failed login attempts
        const suspiciousIPs = await ActivityLog.aggregate([
            {
                $match: {
                    action: { $in: ['login_failed', 'suspicious_activity', 'rate_limit_exceeded'] },
                    timestamp: { $gte: oneDayAgo }
                }
            },
            {
                $group: {
                    _id: '$ipAddress',
                    failedAttempts: {
                        $sum: {
                            $cond: [{ $eq: ['$action', 'login_failed'] }, 1, 0]
                        }
                    },
                    suspiciousActivities: {
                        $sum: {
                            $cond: [{ $eq: ['$action', 'suspicious_activity'] }, 1, 0]
                        }
                    },
                    rateLimitViolations: {
                        $sum: {
                            $cond: [{ $eq: ['$action', 'rate_limit_exceeded'] }, 1, 0]
                        }
                    },
                    totalEvents: { $sum: 1 },
                    lastActivity: { $max: '$timestamp' }
                }
            },
            {
                $match: {
                    $or: [
                        { failedAttempts: { $gte: 5 } },
                        { suspiciousActivities: { $gte: 3 } },
                        { rateLimitViolations: { $gte: 2 } }
                    ]
                }
            },
            {
                $sort: { totalEvents: -1 }
            },
            {
                $limit: 20
            }
        ]);

        res.status(200).json({
            status: 'success',
            data: suspiciousIPs
        });
    } catch (error) {
        console.error('Error getting suspicious IPs:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error retrieving suspicious IP addresses'
        });
    }
});

// Get security events with filtering
const getSecurityEvents = asyncHandler(async (req, res) => {
    try {
        const { page = 1, limit = 50, action, severity, ipAddress, startDate, endDate } = req.query;
        const skip = (page - 1) * limit;

        // Build filter object
        const filter = {};

        if (action) filter.action = action;
        if (severity) filter.severity = severity;
        if (ipAddress) filter.ipAddress = { $regex: ipAddress, $options: 'i' };

        if (startDate || endDate) {
            filter.timestamp = {};
            if (startDate) filter.timestamp.$gte = new Date(startDate);
            if (endDate) filter.timestamp.$lte = new Date(endDate);
        }

        const events = await ActivityLog.find(filter)
            .populate('userId', 'fname email')
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await ActivityLog.countDocuments(filter);

        res.status(200).json({
            status: 'success',
            data: {
                events,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / limit),
                    totalEvents: total,
                    hasNextPage: page * limit < total,
                    hasPrevPage: page > 1
                }
            }
        });
    } catch (error) {
        console.error('Error getting security events:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error retrieving security events'
        });
    }
});

// Export security logs
const exportSecurityLogs = asyncHandler(async (req, res) => {
    try {
        const { startDate, endDate, action, severity } = req.query;

        // Build filter object
        const filter = {};

        if (action) filter.action = action;
        if (severity) filter.severity = severity;

        if (startDate || endDate) {
            filter.timestamp = {};
            if (startDate) filter.timestamp.$gte = new Date(startDate);
            if (endDate) filter.timestamp.$lte = new Date(endDate);
        }

        const logs = await ActivityLog.find(filter)
            .populate('userId', 'fname email')
            .sort({ timestamp: -1 })
            .lean();

        // Convert to CSV format
        const csvHeaders = [
            'Timestamp',
            'User ID',
            'User Name',
            'User Email',
            'Action',
            'Severity',
            'IP Address',
            'User Agent',
            'Resource',
            'Method',
            'Status Code',
            'Metadata'
        ];

        const csvData = logs.map(log => [
            log.timestamp.toISOString(),
            log.userId?._id || 'N/A',
            log.userId?.fname || 'N/A',
            log.userId?.email || 'N/A',
            log.action,
            log.severity,
            log.ipAddress,
            log.userAgent || 'N/A',
            log.resource || 'N/A',
            log.method || 'N/A',
            log.statusCode || 'N/A',
            JSON.stringify(log.metadata || {})
        ]);

        const csvContent = [csvHeaders, ...csvData]
            .map(row => row.map(field => `"${field}"`).join(','))
            .join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="security_logs_${new Date().toISOString().split('T')[0]}.csv"`);

        res.status(200).send(csvContent);
    } catch (error) {
        console.error('Error exporting security logs:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error exporting security logs'
        });
    }
});

// Get system health metrics
const getSystemHealth = asyncHandler(async (req, res) => {
    try {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Database connection status
        const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';

        // Recent error count
        const recentErrors = await ActivityLog.countDocuments({
            severity: { $in: ['high', 'critical'] },
            timestamp: { $gte: oneHourAgo }
        });

        // System uptime (simplified)
        const uptime = process.uptime();

        // Memory usage
        const memoryUsage = process.memoryUsage();

        res.status(200).json({
            status: 'success',
            data: {
                database: {
                    status: dbStatus,
                    connectionState: mongoose.connection.readyState
                },
                errors: {
                    recentErrors: recentErrors,
                    lastHour: recentErrors
                },
                system: {
                    uptime: Math.floor(uptime),
                    memoryUsage: {
                        rss: Math.round(memoryUsage.rss / 1024 / 1024), // MB
                        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
                        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) // MB
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error getting system health:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error retrieving system health metrics'
        });
    }
});

module.exports = {
    getSecurityMetrics,
    getSecurityTrends,
    getSuspiciousIPs,
    getSecurityEvents,
    exportSecurityLogs,
    getSystemHealth
}; 
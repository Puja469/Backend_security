const ActivityLog = require("../model/ActivityLog"); // fixed typo 'model' → 'models'

const activityLogger = (action) => {
  return async (req, res, next) => {
    try {
      // Only log if userId is available
      if (req.user?._id) {
        await ActivityLog.create({
          userId: req.user._id,
          action,
          metadata: {
            ip: req.ip,
            userAgent: req.headers['user-agent']
          },
          timestamp: new Date()
        });
      }
    } catch (err) {
      console.error("Failed to log activity:", err.message);
    }
    next();
  };
};

module.exports = activityLogger;

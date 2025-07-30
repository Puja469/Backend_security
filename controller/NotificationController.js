const Notification = require("../model/Notification");

const getNotifications = async (req, res) => {
    try {
        const userId = req.user._id; // Use from protect middleware

        const notifications = await Notification.find({ userId }).sort({ createdAt: -1 });
        res.status(200).json(notifications);
    } catch (error) {
        console.error("Error fetching notifications:", error);
        res.status(500).json({ error: "Failed to fetch notifications" });
    }
};


const markNotificationsAsRead = async (req, res) => {
    try {
        const userId = req.user._id;

        await Notification.updateMany({ userId, isRead: false }, { isRead: true });
        res.status(200).json({ message: "Notifications marked as read" });
    } catch (error) {
        console.error("Error marking notifications as read:", error);
        res.status(500).json({ error: "Failed to mark notifications as read" });
    }
};

module.exports = {
    getNotifications,
    markNotificationsAsRead,
};

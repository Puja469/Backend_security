const mongoose = require("mongoose");

const NotificationSchema = new mongoose.Schema({
    userId: {
         type: mongoose.Schema.Types.ObjectId,
          ref: "Users", 
          required: true },
    message: {
         type: String, 
         required: true },
    isRead: { 
        type: Boolean,
         default: false },
    createdAt: {
         type: Date, 
         default: Date.now },
});

module.exports = mongoose.model("Notification", NotificationSchema);

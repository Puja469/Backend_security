const Comment = require("../model/Comment");
const Item = require("../model/Item");
const Notification = require("../model/Notification");

const addComment = async (req, res) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({ message: "Unauthorized. Please log in." });
      }
  
      const { itemId, text } = req.body;
      if (!itemId || !text) {
        return res.status(400).json({ message: "Item ID and text are required" });
      }
  
      // Find the product being commented on
      const item = await Item.findById(itemId).populate("sellerId");
      if (!item) return res.status(404).json({ message: "Product not found" });
  
      // Save the comment
      const comment = new Comment({ itemId, userId: req.user.id, text });
      await comment.save();
  
      // ✅ Create a notification with product link
      const productLink = `http://localhost:5173/product/${itemId}`;
      const notificationMessage = `Your product "${item.name}" received a new comment: "${text}". Click here to view: ${productLink}`;
  
      const notification = new Notification({
        userId: item.sellerId._id, // Product owner's ID
        message: notificationMessage,
        isRead: false,
        itemId, // To track which product got the comment
      });
  
      await notification.save();
  
      // ✅ Emit notification via Socket.IO
      const io = req.app.get("socketio");
      if (io) {
        io.to(item.sellerId._id.toString()).emit("newNotification", { 
          message: notificationMessage, 
          itemId,
          link: productLink
        });
        console.log(`Notification sent to user: ${item.sellerId._id}`);
      }
  
      res.status(201).json({ message: "Comment added successfully", comment });
  
    } catch (error) {
      console.error("Error adding comment:", error);
      res.status(500).json({ message: "Error adding comment", error: error.message });
    }
  };
  
  const getCommentsByItem = async (req, res) => {
    try {
      const { itemId } = req.params;
      const comments = await Comment.find({ itemId })
        .populate("userId", "fname email image") // Include "image" here
        .populate("replies.userId", "fname email image"); // Include "image" here
      res.status(200).json(comments);
    } catch (error) {
      res.status(500).json({ message: "Error fetching comments", error: error.message });
    }
  };

  const replyToComment = async (req, res) => {
    try {
      const { commentId } = req.params;
      const { text } = req.body;
      const userId = req.user.id; // Logged-in user
  
      if (!text || !text.trim()) {
        return res.status(400).json({ message: "Reply text cannot be empty." });
      }
  
      const comment = await Comment.findById(commentId);
      if (!comment) return res.status(404).json({ message: "Comment not found" });
  
      // ✅ Fetch the product related to this comment
      const item = await Item.findById(comment.itemId).populate("sellerId").exec();
      if (!item) return res.status(404).json({ message: "Product not found" });
  
      // ❌ Restrict Replying: Only Product Owner (Seller) Can Reply
      if (userId !== item.sellerId._id.toString()) {
        return res.status(403).json({ message: "Only the product owner can reply to comments." });
      }
  
      // ✅ Add reply from the seller
      comment.replies.push({ userId, text });
      await comment.save();
  
      res.status(200).json({ message: "Reply added successfully", comment });
    } catch (error) {
      console.error("Error replying to comment:", error);
      res.status(500).json({ message: "Error replying to comment", error: error.message });
    }
  };
  
// ✅ Delete a comment (only by owner or admin)
const deleteComment = async (req, res) => {
  try {
    const { commentId } = req.params;
    const userId = req.user.id; // Logged-in user

    const comment = await Comment.findById(commentId);
    if (!comment) return res.status(404).json({ message: "Comment not found" });

    // Ensure the logged-in user is the comment owner or admin
    if (comment.userId.toString() !== userId) {
      return res.status(403).json({ message: "Not authorized to delete this comment" });
    }

    await comment.deleteOne();
    res.status(200).json({ message: "Comment deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting comment", error: error.message });
  }
};

module.exports = {
  addComment,
  getCommentsByItem,
  replyToComment,
  deleteComment,
};

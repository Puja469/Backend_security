const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema({
  itemId: {
     type: mongoose.Schema.Types.ObjectId,
      ref: "Items",
       required: true },
  buyerId: {
     type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
       required: true },
  sellerId: {
     type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
       required: true },
  status: { 
    type: String, 
    enum: ["pending", "paid", "shipped", "delivered"], 
    default: "pending" 
  },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Order", OrderSchema);

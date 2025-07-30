const Order = require("../model/Order");
const Item = require("../model/Item");

const createOrder = async (req, res) => {
  try {
    const { itemId, buyerId } = req.body;

    const item = await Item.findById(itemId);
    
    console.log("Fetched Item:", item);

    if (!item) {
      return res.status(404).json({ error: "Item not found" });
    }

    if (!item.sellerId) {
      return res.status(500).json({ error: "Seller ID is missing for this item" });
    }

    if (item.sellerId.toString() === buyerId) {
      return res.status(400).json({ error: "You cannot buy your own item" });
    }

    const existingOrder = await Order.findOne({ itemId });
    if (existingOrder) {
      return res.status(400).json({ error: "This item is already ordered." });
    }

    const order = new Order({
      itemId,
      buyerId,
      sellerId: item.sellerId, 
      status: "pending",
    });
    await order.save();

    res.json({ message: "Order placed successfully", order });
  } catch (error) {
    console.error("Error in createOrder:", error.message);
    res.status(500).json({ error: "Something went wrong", details: error.message });
  }
};


const getUserOrders = async (req, res) => {
  try {
    const userId = req.params.userId;
    const orders = await Order.find({ buyerId: userId }).populate("itemId");
    res.json({ myOrders: orders });
  } catch (error) {
    res.status(500).json({ error: "Error fetching orders" });
  }
};

const getSoldItems = async (req, res) => {
  try {
    const userId = req.params.userId;
    const soldItems = await Order.find({ sellerId: userId }).populate("itemId");
    res.json({ soldItems });
  } catch (error) {
    res.status(500).json({ error: "Error fetching sold items" });
  }
};


const updateOrderStatus = async (req, res) => {
  try {
    const { orderId, status, userId } = req.body;

    
    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ error: "Order not found" });

   
    if (order.sellerId.toString() !== userId) {
      return res.status(403).json({ error: "Only the seller can update order status." });
    }

    const validStatuses = ["pending", "paid", "shipped", "delivered"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid order status." });
    }

    const statusFlow = {
      pending: ["paid"],
      paid: ["shipped"],
      shipped: ["delivered"],
    };

    if (!statusFlow[order.status]?.includes(status)) {
      return res.status(400).json({
        error: `You can only change status from "${order.status}" to "${statusFlow[order.status]?.join('" or "')}".`
      });
    }

    order.status = status;
    await order.save();

    if (status === "delivered") {
      await Item.findByIdAndUpdate(order.itemId, { status: "sold" });
    }

    res.json({ message: `Order marked as "${status}" successfully!`, order });
  } catch (error) {
    res.status(500).json({ error: "Error updating order status", details: error.message });
  }
};

module.exports = {
  createOrder,
  getUserOrders,
  getSoldItems,
  updateOrderStatus
};

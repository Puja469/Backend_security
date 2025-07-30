const Item= require("../model/Item")
const SubCategory = require('../model/SubCategory'); 
const Notification = require("../model/Notification");





const findAll = async (req, res) => {
    try {
        const { sellerId, subcategoryName, status } = req.query;
        let query = {};

        if (sellerId) query.sellerId = sellerId;

        if (subcategoryName) {
            const subcategory = await SubCategory.findOne({ subcategory_name: subcategoryName });

            if (subcategory) {
                query.subcategoryId = subcategory._id;
            } else {
                return res.status(404).json({ error: "Subcategory not found" });
            }
        }

        if (status) {
            // Ensure the status value is valid
            if (!["Pending", "Approved", "Rejected"].includes(status)) {
                return res.status(400).json({ error: "Invalid status value" });
            }
            query.status = status;
        }

        const items = await Item.find(query).populate([
            "sellerId",
            "subcategoryId",
            "categoryId",
        ]);

        return res.status(200).json(items);
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: "Failed to fetch items", details: error.message });
    }
};



// const save = async(req,res) =>{
//     try {

//         const{name,price,description,date,sellerId,subcategoryId,categoryId,isRefundable,isExchangeable} = req.body
        
//         const item = new Item({
//             name,
//             price,
//             description,
//             date,
//             sellerId,
//             categoryId,
//             subcategoryId,
//             image:req.file.originalname,
//             isRefundable ,
//             isExchangeable ,
//             viewCount: "0",
//             status: 'Pending',
            
//         });
//         await item.save();
//         res.status(201).json(item)
//     } catch (e){
//         res.json(e)
//     }
// }

const save = async (req, res) => {
    try {
        const { name, price, description, date, sellerId, subcategoryId, categoryId, isRefundable, isExchangeable } = req.body;

        if (!name || !price || !description || !date || !sellerId || !subcategoryId || !categoryId) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        const item = new Item({
            name,
            price,
            description,
            date,
            sellerId,
            categoryId,
            subcategoryId,
            image: req.file ? req.file.originalname : "default-image.jpg",  // Set default image if no file is uploaded
            isRefundable,
            isExchangeable,
            viewCount: "0",
            status: "Pending",
        });

        const savedItem = await item.save(); // Save and store the item

        console.log("Saved Item:", savedItem); // Debugging - Check if item is properly saved

        res.status(201).json({
            message: "Item created successfully",
            item: savedItem, // Include the full saved item object in the response
        });

    } catch (e) {
        console.error("Error saving item:", e);
        res.status(500).json({ message: "Error saving item", error: e.message });
    }
};

// const findById = async (req, res) => {
//     try {
//         const item = await Item.findById(req.params.id)
//             .populate({
//                 path: 'sellerId',
//                 select: 'fname email phone city image', 
//             })
//             .populate({
//                 path: 'categoryId',
//                 select: 'category_name', 
//             })
//             .populate({
//                 path: 'subcategoryId',
//                 select: 'subcategory_name', 
//             });

//         if (!item) {
//             return res.status(404).json({ error: "Item not found" });
//         }

//         res.status(200).json(item);
//     } catch (e) {
//         console.error("Error fetching item by ID:", e);
//         res.status(500).json({ error: "Failed to fetch item", details: e.message });
//     }
// };

const findById = async (req,res)=>{
    try{
        const item= await Item.findById(req.params.id);
        res.status(200).json(item)

    }catch (e) {
        res.json(e)

    }
};




const deleteById = async (req,res)=>{
    try{
        const item= await Item.findByIdAndDelete(req.params.id);
        res.status(200).json("data deleted")

    }catch (e) {
        res.json(e)

    }
}

const update = async (req,res)=>{
    try{
        const item= await Item.findByIdAndUpdate(req.params.id,req.body,{new:true});
        res.status(202).json(item)

    }catch (e) {
        res.json(e)

    }
}

const updateStatus = async (req, res) => {
    try {
        const { status } = req.body;
        const itemId = req.params.id;

        if (!["Pending", "Approved", "Rejected"].includes(status)) {
            return res.status(400).json({ error: "Invalid status value" });
        }

        const item = await Item.findByIdAndUpdate(itemId, { status }, { new: true }).populate("sellerId");

        if (!item) {
            return res.status(404).json({ error: "Item not found" });
        }

        const sellerId = item.sellerId._id.toString();
        const message = `Your product "${item.name}" has been ${status}.`;

        // Save the notification in the database
        const notification = new Notification({
            userId: sellerId,
            message,
            isRead: false,
        });
        await notification.save();

        // Emit the notification via Socket.IO
        const io = req.app.get("socketio");
        if (io) {
            io.to(sellerId).emit("notification", { message });
            console.log(`Notification sent to user room: ${sellerId}`);
        }

        res.status(200).json({ message: `Item status updated to ${status}`, item });
    } catch (error) {
        console.error("Error updating item status:", error);
        res.status(500).json({ error: "Error updating item status", details: error.message });
    }
};
const incrementViewCount = async (req, res) => {
    try {
        const { userId } = req.body; 
        const item = await Item.findById(req.params.id);

        if (!item) {
            return res.status(404).json({ error: "Item not found" });
        }

        if (!item.viewedBy.includes(userId)) {
            const currentViewCount = parseInt(item.viewCount || '0', 10);
            item.viewCount = (currentViewCount + 1).toString();
            item.viewedBy.push(userId); 
            await item.save();
        }

        res.status(200).json({ message: "View count incremented", viewCount: item.viewCount });
    } catch (e) {
        res.status(500).json({ error: "Failed to increment view count", details: e.message });
    }
};



const getViewCount = async (req, res) => {
    try {
        const item = await Item.findById(req.params.id, 'viewCount');

        if (!item) {
            return res.status(404).json({ error: "Item not found" });
        }

        res.status(200).json({ viewCount: item.viewCount });
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch view count", details: e.message });
    }
};









module.exports={
    findAll,
    save,
    findById,
    deleteById,
    update,
    incrementViewCount,
    getViewCount,
    updateStatus,
   
    
    
}
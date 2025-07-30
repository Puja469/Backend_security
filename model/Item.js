const mongoose= require("mongoose")

const itemSchema = new mongoose.Schema({

    sellerId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"Users"

    },
    categoryId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Categories",
        required: true,
      },

    subcategoryId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"SubCategories"
    },

    name : {
        type: String,
        required: true
    },
    price :{
        type: String,
        required:true,
        min: 0
    },
    image:{
        type: String,
        required: true
    },
    description:{
        type: String,
        required: true
    },
    date:{
        type: String,
        required: true
    },
    isRefundable: {
        type: String,
        default: "no"
      },
      isExchangeable: {
        type: String,
        default: "no"
      },

      viewCount: { 
        type: String,
        default: '0'
     },
     viewedBy: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Users", 
        },
        
      ],
      status: {
        type: String,
        enum: ['Pending', 'Approved', 'Rejected'],
        default: 'Pending',
      },


})
const Item =mongoose.model("Items",itemSchema);
module.exports= Item;




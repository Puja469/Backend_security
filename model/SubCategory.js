const mongoose= require("mongoose")

const subcategorySchema = new mongoose.Schema({


    categoryId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"Categories",
        required: true

    },
    subcategory_name : {
        type: String,
        required: true
    }



})
const SubCategory =mongoose.model("SubCategories",subcategorySchema);
module.exports= SubCategory;




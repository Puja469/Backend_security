const mongoose= require("mongoose")

const categorySchema = new mongoose.Schema({

    category_name : {
        type: String,
        required: true
    }



})
const Category =mongoose.model("Categories",categorySchema);
module.exports= Category;




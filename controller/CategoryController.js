const Category= require("../model/Category")

const findAll =async (req,res) =>{
    try {

        const categories = await Category.find();
        res.status(200).json(categories);
    } catch (e){
        res.json(e)
    }

}
const save = async(req,res) =>{
    try {
        const category = new Category(req.body);
        await category.save();
        res.status(201).json(category)
    } catch (e){
        res.json(e)
    }
}
const findById = async (req,res)=>{
    try{
        const category= await Category.findById(req.params.id);
        res.status(200).json(category)

    }catch (e) {
        res.json(e)

    }
}
const deleteById = async (req,res)=>{
    try{
        const category= await Category.findByIdAndDelete(req.params.id);
        res.status(200).json("data deleted")

    }catch (e) {
        res.json(e)

    }
}

const update = async (req,res)=>{
    try{
        const category= await Category.findByIdAndUpdate(req.params.id,req.body,{new:true});
        res.status(202).json(category)

    }catch (e) {
        res.json(e)

    }
}

module.exports={
    findAll,
    save,
    findById,
    deleteById,
    update
}
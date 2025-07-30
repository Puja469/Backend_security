const SubCategory = require("../model/SubCategory");


const findAll = async (req, res) => {
  try {
    const subcategories = await SubCategory.find().populate("categoryId"); // Populate category details
    res.status(200).json(subcategories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const save = async (req, res) => {
  try {
    const { categoryId, subcategory_name } = req.body;

    if (!categoryId || !subcategory_name) {
      return res.status(400).json({ message: "categoryId and subcategory_name are required" });
    }

    const subcategory = new SubCategory(req.body);
    await subcategory.save();
    res.status(201).json({ message: "Subcategory created successfully", subcategory });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const findById = async (req, res) => {
  try {
    const subcategory = await SubCategory.findById(req.params.id).populate("categoryId");
    if (!subcategory) {
      return res.status(404).json({ message: "Subcategory not found" });
    }
    res.status(200).json(subcategory);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const deleteById = async (req, res) => {
  try {
    const subcategory = await SubCategory.findByIdAndDelete(req.params.id);
    if (!subcategory) {
      return res.status(404).json({ message: "Subcategory not found" });
    }
    res.status(200).json({ message: "Subcategory deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const update = async (req, res) => {
  try {
    const { subcategory_name } = req.body;

    if (!subcategory_name) {
      return res.status(400).json({ message: "subcategory_name is required" });
    }

    const subcategory = await SubCategory.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!subcategory) {
      return res.status(404).json({ message: "Subcategory not found" });
    }
    res.status(202).json({ message: "Subcategory updated successfully", subcategory });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


module.exports = {
  findAll,
  save,
  findById,
  deleteById,
  update,
};

const joi = require("joi");

const userSchema = joi.object({
    fname: joi.string().required(),
    email: joi.string().required().email(),
    phone: joi.string().required(),
    city: joi.string().required(),
    password: joi.string().required()





})

function UserValidation(req, res, next) {
    const { fname, email, phone, city, password } = req.body;
    const { error } = userSchema.validate({ fname, email, phone, city, password })
    if (error) {
        return res.json(error)
    }
    next()

}

module.exports = UserValidation;
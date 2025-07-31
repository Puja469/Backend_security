const joi = require("joi");

const userSchema = joi.object({
    fname: joi.string().required(),
    email: joi.string().required().email(),
    phone: joi.string().required(),
    city: joi.string().required(),
    password: joi.string().required()
});

const emailVerificationSchema = joi.object({
    email: joi.string().required().email(),
    otp: joi.string().required().length(6).pattern(/^\d+$/)
});

const sendOTPSchema = joi.object({
    email: joi.string().required().email()
});

function UserValidation(req, res, next) {
    const { fname, email, phone, city, password } = req.body;
    const { error } = userSchema.validate({ fname, email, phone, city, password })
    if (error) {
        return res.status(400).json({
            status: 'error',
            message: 'Validation failed',
            details: error.details.map(detail => detail.message)
        });
    }
    next();
}

function EmailVerificationValidation(req, res, next) {
    const { email, otp } = req.body;
    const { error } = emailVerificationSchema.validate({ email, otp });
    if (error) {
        return res.status(400).json({
            status: 'error',
            message: 'Invalid email or OTP format',
            details: error.details.map(detail => detail.message)
        });
    }
    next();
}

function SendOTPValidation(req, res, next) {
    const { email } = req.body;
    const { error } = sendOTPSchema.validate({ email });
    if (error) {
        return res.status(400).json({
            status: 'error',
            message: 'Invalid email format',
            details: error.details.map(detail => detail.message)
        });
    }
    next();
}

module.exports = {
    UserValidation,
    EmailVerificationValidation,
    SendOTPValidation
};
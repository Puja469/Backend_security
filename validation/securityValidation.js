const Joi = require('joi');

// Email validation schema
const emailSchema = Joi.string()
  .email({ tlds: { allow: false } })
  .max(254)
  .required()
  .messages({
    'string.email': 'Please provide a valid email address',
    'string.max': 'Email address is too long',
    'any.required': 'Email is required'
  });

// Password validation schema
const passwordSchema = Joi.string()
  .min(8)
  .max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])/)
  .required()
  .messages({
    'string.min': 'Password must be at least 8 characters long',
    'string.max': 'Password is too long',
    'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
    'any.required': 'Password is required'
  });

// Name validation schema
const nameSchema = Joi.string()
  .min(2)
  .max(50)
  .pattern(/^[a-zA-Z\s]+$/)
  .required()
  .messages({
    'string.min': 'Name must be at least 2 characters long',
    'string.max': 'Name is too long',
    'string.pattern.base': 'Name can only contain letters and spaces',
    'any.required': 'Name is required'
  });

// Phone number validation schema
const phoneSchema = Joi.string()
  .pattern(/^[\+]?[1-9][\d]{0,15}$/)
  .max(20)
  .messages({
    'string.pattern.base': 'Please provide a valid phone number',
    'string.max': 'Phone number is too long'
  });

// URL validation schema
const urlSchema = Joi.string()
  .uri()
  .max(2048)
  .messages({
    'string.uri': 'Please provide a valid URL',
    'string.max': 'URL is too long'
  });

// ID validation schema (MongoDB ObjectId)
const idSchema = Joi.string()
  .pattern(/^[0-9a-fA-F]{24}$/)
  .required()
  .messages({
    'string.pattern.base': 'Invalid ID format',
    'any.required': 'ID is required'
  });

// Pagination validation schema
const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(10),
  sort: Joi.string().valid('asc', 'desc').default('desc'),
  sortBy: Joi.string().max(50).default('createdAt')
});

// Search validation schema
const searchSchema = Joi.object({
  q: Joi.string().max(100).allow(''),
  category: Joi.string().max(50).allow(''),
  price: Joi.object({
    min: Joi.number().min(0),
    max: Joi.number().min(0)
  }).when('max', {
    is: Joi.exist(),
    then: Joi.object({
      min: Joi.number().max(Joi.ref('max'))
    })
  })
});

// User registration validation
const userRegistrationSchema = Joi.object({
  firstName: nameSchema,
  lastName: nameSchema,
  email: emailSchema,
  password: passwordSchema,
  phone: phoneSchema.optional(),
  role: Joi.string().valid('user', 'admin').default('user')
});

// Regular user registration validation (for /api/auth/register)
const regularUserRegistrationSchema = Joi.object({
  fname: Joi.string().min(2).max(50).required().messages({
    'string.min': 'Name must be at least 2 characters long',
    'string.max': 'Name is too long',
    'any.required': 'Name is required'
  }),
  email: emailSchema,
  phone: phoneSchema.required().messages({
    'any.required': 'Phone number is required'
  }),
  city: Joi.string().min(2).max(50).required().messages({
    'string.min': 'City must be at least 2 characters long',
    'string.max': 'City name is too long',
    'any.required': 'City is required'
  }),
  password: passwordSchema
});

// Admin registration validation
const adminRegistrationSchema = Joi.object({
  fname: Joi.string().min(2).max(50).required().messages({
    'string.min': 'Name must be at least 2 characters long',
    'string.max': 'Name is too long',
    'any.required': 'Name is required'
  }),
  email: emailSchema,
  password: passwordSchema,
  phone: phoneSchema.optional(),
  role: Joi.string().valid('admin').default('admin')
});

// User login validation
const userLoginSchema = Joi.object({
  email: emailSchema,
  password: Joi.string().required().messages({
    'any.required': 'Password is required'
  })
});

// User update validation
const userUpdateSchema = Joi.object({
  firstName: nameSchema.optional(),
  lastName: nameSchema.optional(),
  email: emailSchema.optional(),
  phone: phoneSchema.optional(),
  bio: Joi.string().max(500).optional(),
  address: Joi.object({
    street: Joi.string().max(100).optional(),
    city: Joi.string().max(50).optional(),
    state: Joi.string().max(50).optional(),
    zipCode: Joi.string().max(10).optional(),
    country: Joi.string().max(50).optional()
  }).optional()
});

// Password reset validation
const passwordResetSchema = Joi.object({
  email: emailSchema,
  otp: Joi.string().length(6).pattern(/^\d+$/).required().messages({
    'string.length': 'OTP must be 6 digits',
    'string.pattern.base': 'OTP must contain only numbers',
    'any.required': 'OTP is required'
  }),
  newPassword: passwordSchema
});

// Item creation validation
const itemCreationSchema = Joi.object({
  name: Joi.string().min(3).max(100).required().messages({
    'string.min': 'Name must be at least 3 characters long',
    'string.max': 'Name is too long',
    'any.required': 'Name is required'
  }),
  description: Joi.string().min(10).max(1000).required().messages({
    'string.min': 'Description must be at least 10 characters long',
    'string.max': 'Description is too long',
    'any.required': 'Description is required'
  }),
  price: Joi.string().required().messages({
    'any.required': 'Price is required'
  }),
  date: Joi.string().required().messages({
    'any.required': 'Date is required'
  }),
  sellerId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required().messages({
    'string.pattern.base': 'Invalid seller ID format',
    'any.required': 'Seller ID is required'
  }),
  categoryId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required().messages({
    'string.pattern.base': 'Invalid category ID format',
    'any.required': 'Category ID is required'
  }),
  subcategoryId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required().messages({
    'string.pattern.base': 'Invalid subcategory ID format',
    'any.required': 'Subcategory ID is required'
  }),
  isRefundable: Joi.string().valid('yes', 'no').default('no'),
  isExchangeable: Joi.string().valid('yes', 'no').default('no'),
  status: Joi.string().valid('Pending', 'Approved', 'Rejected').default('Pending').optional()
});

// Comment validation
const commentSchema = Joi.object({
  content: Joi.string().min(1).max(500).required().messages({
    'string.min': 'Comment cannot be empty',
    'string.max': 'Comment is too long',
    'any.required': 'Comment content is required'
  }),
  itemId: idSchema,
  parentId: idSchema.optional() // For nested comments
});

// Order validation
const orderSchema = Joi.object({
  items: Joi.array().items(Joi.object({
    itemId: idSchema,
    quantity: Joi.number().integer().min(1).max(100).required()
  })).min(1).required(),
  shippingAddress: Joi.object({
    street: Joi.string().max(100).required(),
    city: Joi.string().max(50).required(),
    state: Joi.string().max(50).required(),
    zipCode: Joi.string().max(10).required(),
    country: Joi.string().max(50).required()
  }).required(),
  paymentMethod: Joi.string().valid('credit_card', 'paypal', 'stripe').required()
});

module.exports = {
  emailSchema,
  passwordSchema,
  nameSchema,
  phoneSchema,
  urlSchema,
  idSchema,
  paginationSchema,
  searchSchema,
  userRegistrationSchema,
  regularUserRegistrationSchema,
  adminRegistrationSchema,
  userLoginSchema,
  userUpdateSchema,
  passwordResetSchema,
  itemCreationSchema,
  commentSchema,
  orderSchema
}; 
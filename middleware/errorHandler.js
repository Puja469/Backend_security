const errorHandler = (err, req, res, next) => {
    let error = { ...err };
    error.message = err.message;

    // Log error details for debugging
    console.error('Error Handler:', {
        message: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        timestamp: new Date().toISOString(),
        userId: req.user ? req.user._id : 'anonymous'
    });

    // Mongoose bad ObjectId
    if (err.name === 'CastError') {
        const message = 'Resource not found';
        error = { message, statusCode: 404 };
    }

    // Mongoose duplicate key
    if (err.code === 11000) {
        const message = 'Duplicate field value entered';
        error = { message, statusCode: 400 };
    }

    // Mongoose validation error
    if (err.name === 'ValidationError') {
        const message = Object.values(err.errors).map(val => val.message).join(', ');
        error = { message, statusCode: 400 };
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        const message = 'Invalid token';
        error = { message, statusCode: 401 };
    }

    if (err.name === 'TokenExpiredError') {
        const message = 'Token expired';
        error = { message, statusCode: 401 };
    }

    // Rate limit errors
    if (err.status === 429) {
        const message = 'Too many requests, please try again later';
        error = { message, statusCode: 429 };
    }

    // File upload errors
    if (err.code === 'LIMIT_FILE_SIZE') {
        const message = 'File too large';
        error = { message, statusCode: 400 };
    }

    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
        const message = 'Unexpected file field';
        error = { message, statusCode: 400 };
    }

    // Security-related errors
    if (err.message && err.message.includes('suspicious')) {
        const message = 'Suspicious activity detected';
        error = { message, statusCode: 400 };
    }

    // Default error
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Server Error';

    // Don't expose internal error details in production
    const errorResponse = {
        status: 'error',
        message: process.env.NODE_ENV === 'production' && statusCode === 500
            ? 'An error occurred while processing your request'
            : message,
        ...(process.env.NODE_ENV === 'development' && {
            stack: err.stack,
            details: error
        })
    };

    res.status(statusCode).json(errorResponse);
};

module.exports = errorHandler; 
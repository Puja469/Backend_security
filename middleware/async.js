const asyncHandler = fn => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((error) => {
        // Log error details for debugging (but don't expose sensitive info)
        console.error('Async Error:', {
            message: error.message,
            stack: error.stack,
            url: req.url,
            method: req.method,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            timestamp: new Date().toISOString()
        });

        // Don't expose internal error details to client
        const errorResponse = {
            status: 'error',
            message: process.env.NODE_ENV === 'production'
                ? 'An error occurred while processing your request'
                : error.message
        };

        // Set appropriate status code
        const statusCode = error.statusCode || 500;

        res.status(statusCode).json(errorResponse);
    });
};

module.exports = asyncHandler;
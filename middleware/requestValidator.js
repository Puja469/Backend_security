const requestValidator = (req, res, next) => {
    // Validate request method
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({
            status: 'error',
            message: 'Method not allowed'
        });
    }

    // Validate Content-Type for POST/PUT requests
    if ((req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') &&
        req.headers['content-type'] &&
        !req.headers['content-type'].includes('application/json') &&
        !req.headers['content-type'].includes('multipart/form-data')) {
        return res.status(400).json({
            status: 'error',
            message: 'Invalid Content-Type. Expected application/json or multipart/form-data'
        });
    }

    // Validate request size
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (contentLength > maxSize) {
        return res.status(413).json({
            status: 'error',
            message: 'Request entity too large'
        });
    }

    // Validate URL length
    const maxUrlLength = 2048;
    if (req.url.length > maxUrlLength) {
        return res.status(414).json({
            status: 'error',
            message: 'URI too long'
        });
    }

    // Validate query parameters
    const queryParams = Object.keys(req.query);
    if (queryParams.length > 50) {
        return res.status(400).json({
            status: 'error',
            message: 'Too many query parameters'
        });
    }

    // Check for suspicious query parameters
    const suspiciousParams = ['__proto__', 'constructor', 'prototype'];
    for (const param of suspiciousParams) {
        if (queryParams.includes(param)) {
            return res.status(400).json({
                status: 'error',
                message: 'Suspicious query parameter detected'
            });
        }
    }

    // Validate request headers
    const requiredHeaders = ['user-agent'];
    for (const header of requiredHeaders) {
        if (!req.headers[header]) {
            return res.status(400).json({
                status: 'error',
                message: `Missing required header: ${header}`
            });
        }
    }

    // Block suspicious user agents
    const suspiciousUserAgents = [
        /bot/i,
        /crawler/i,
        /spider/i,
        /scraper/i,
        /curl/i,
        /wget/i
    ];

    const userAgent = req.headers['user-agent'] || '';
    for (const pattern of suspiciousUserAgents) {
        if (pattern.test(userAgent)) {
            return res.status(403).json({
                status: 'error',
                message: 'Access denied'
            });
        }
    }

    // Validate request body for JSON requests
    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
        if (req.body && typeof req.body === 'object') {
            // Check for circular references
            try {
                JSON.stringify(req.body);
            } catch (error) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid request body'
                });
            }

            // Check for suspicious properties
            const suspiciousProps = ['__proto__', 'constructor', 'prototype'];
            const checkObject = (obj) => {
                for (const key in obj) {
                    if (suspiciousProps.includes(key)) {
                        return false;
                    }
                    if (typeof obj[key] === 'object' && obj[key] !== null) {
                        if (!checkObject(obj[key])) {
                            return false;
                        }
                    }
                }
                return true;
            };

            if (!checkObject(req.body)) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Suspicious request body detected'
                });
            }
        }
    }

    next();
};

module.exports = requestValidator; 
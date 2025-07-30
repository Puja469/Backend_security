const crypto = require('crypto');

// CAPTCHA configuration
const captchaConfig = {
    length: 5,
    complexity: 'alphanumeric', // 'numeric', 'alphabetic', 'alphanumeric'
    caseSensitive: false,
    expiryTime: 10 * 60 * 1000, // 10 minutes
    maxAttempts: 3
};

// Generate CAPTCHA challenge
const generateCaptcha = () => {
    let chars;
    switch (captchaConfig.complexity) {
        case 'numeric':
            chars = '0123456789';
            break;
        case 'alphabetic':
            chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
            break;
        case 'alphanumeric':
        default:
            chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            break;
    }

    let captcha = '';
    for (let i = 0; i < captchaConfig.length; i++) {
        captcha += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return captcha;
};

// Create CAPTCHA session
const createCaptchaSession = (req) => {
    const captcha = generateCaptcha();
    const sessionId = crypto.randomBytes(16).toString('hex');
    const expiry = Date.now() + captchaConfig.expiryTime;

    // Store CAPTCHA in session (you might want to use Redis in production)
    if (!req.session) {
        req.session = {};
    }

    req.session.captcha = {
        id: sessionId,
        challenge: captcha,
        answer: captchaConfig.caseSensitive ? captcha : captcha.toLowerCase(),
        expiry: expiry,
        attempts: 0
    };

    return {
        sessionId,
        challenge: captcha,
        expiry
    };
};

// Verify CAPTCHA answer
const verifyCaptcha = (req, userAnswer) => {
    if (!req.session || !req.session.captcha) {
        return {
            valid: false,
            error: 'CAPTCHA session not found or expired'
        };
    }

    const captcha = req.session.captcha;

    // Check if CAPTCHA has expired
    if (Date.now() > captcha.expiry) {
        delete req.session.captcha;
        return {
            valid: false,
            error: 'CAPTCHA has expired'
        };
    }

    // Check if max attempts exceeded
    if (captcha.attempts >= captchaConfig.maxAttempts) {
        delete req.session.captcha;
        return {
            valid: false,
            error: 'Maximum CAPTCHA attempts exceeded'
        };
    }

    // Increment attempts
    captcha.attempts++;

    // Normalize user answer
    const normalizedUserAnswer = captchaConfig.caseSensitive
        ? userAnswer
        : userAnswer.toLowerCase();

    // Check if answer is correct
    if (normalizedUserAnswer === captcha.answer) {
        delete req.session.captcha;
        return {
            valid: true,
            message: 'CAPTCHA verification successful'
        };
    } else {
        return {
            valid: false,
            error: 'Incorrect CAPTCHA answer',
            attemptsRemaining: captchaConfig.maxAttempts - captcha.attempts
        };
    }
};

// Middleware to generate CAPTCHA for registration
const generateCaptchaMiddleware = (req, res, next) => {
    try {
        const captchaData = createCaptchaSession(req);

        res.status(200).json({
            status: 'success',
            message: 'CAPTCHA generated successfully',
            data: {
                sessionId: captchaData.sessionId,
                challenge: captchaData.challenge,
                expiry: captchaData.expiry
            }
        });
    } catch (error) {
        console.error('CAPTCHA generation error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error generating CAPTCHA'
        });
    }
};

// Middleware to verify CAPTCHA
const verifyCaptchaMiddleware = (req, res, next) => {
    const { captchaAnswer } = req.body;

    if (!captchaAnswer) {
        return res.status(400).json({
            status: 'error',
            message: 'CAPTCHA answer is required'
        });
    }

    const verification = verifyCaptcha(req, captchaAnswer);

    if (!verification.valid) {
        return res.status(400).json({
            status: 'error',
            message: verification.error,
            attemptsRemaining: verification.attemptsRemaining
        });
    }

    // CAPTCHA is valid, proceed to next middleware
    next();
};

// Rate limiting for CAPTCHA generation
const captchaRateLimit = {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // Max 10 CAPTCHA requests per IP
    message: {
        status: 'error',
        message: 'Too many CAPTCHA requests. Please try again later.'
    }
};

// Enhanced CAPTCHA with image generation (basic ASCII art)
const generateCaptchaImage = (text) => {
    // Simple ASCII art representation
    const lines = [
        '┌─────────────────┐',
        '│                 │',
        '│   ' + text + '   │',
        '│                 │',
        '└─────────────────┘'
    ];

    return lines.join('\n');
};

// CAPTCHA validation for specific routes
const requireCaptcha = (route) => {
    return (req, res, next) => {
        // Only require CAPTCHA for sensitive routes
        const sensitiveRoutes = ['/api/auth/register-user', '/api/auth/login-user'];

        if (sensitiveRoutes.includes(route)) {
            return verifyCaptchaMiddleware(req, res, next);
        }

        next();
    };
};

module.exports = {
    generateCaptcha,
    createCaptchaSession,
    verifyCaptcha,
    generateCaptchaMiddleware,
    verifyCaptchaMiddleware,
    captchaRateLimit,
    generateCaptchaImage,
    requireCaptcha,
    captchaConfig
}; 
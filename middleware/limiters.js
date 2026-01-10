const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 60 * 1000, 
    max: 5, 
    message: { message: 'Too many login attempts, please try again after 1 minute.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, 
    max: 1, 
    message: { message: 'Too many accounts created from this IP, please try again after an hour.' },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = { loginLimiter, registerLimiter };
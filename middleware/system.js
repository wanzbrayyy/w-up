const SystemConfig = require('../models/systemConfig');
const User = require('../models/user');
exports.loadSystemConfig = async (req, res, next) => {
    try {
        const config = await SystemConfig.getConfig();
        if (config.maintenanceMode && !req.path.includes('/login') && !req.path.includes('/admin')) {
            if (req.user && req.user.role === 'admin') {
            } else {
                return res.status(503).send('<h1>Site is under maintenance. Please check back later.</h1>');
            }
        }
        res.locals.systemConfig = config;
        next();
    } catch (e) {
        console.error("System Config Error:", e);
        next();
    }
};

exports.checkBanStatus = async (req, res, next) => {
    if (req.user && req.user.isBanned) {
        res.clearCookie('token');
        res.clearCookie('refresh_token');
        return res.status(403).send(`<h1>Your account has been suspended.</h1><p>Reason: ${req.user.banReason}</p>`);
    }
    next();
};
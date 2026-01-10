const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { checkBanStatus } = require('./system');

exports.protectView = async (req, res, next) => {
    let token;
    if (req.cookies.token) {
        token = req.cookies.token;
    }

    if (!token) {
        return res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const currentUser = await User.findById(decoded.id).select('-password');
        
        if (!currentUser) {
            res.cookie('token', '', { expires: new Date(0) });
            return res.redirect('/login');
        }

        if (currentUser.passwordChangedAt) {
            const changedTimestamp = parseInt(currentUser.passwordChangedAt.getTime() / 1000, 10);
            if (decoded.iat < changedTimestamp) {
                res.cookie('token', '', { expires: new Date(0) });
                return res.redirect('/login');
            }
        }

        req.user = currentUser;
        res.locals.isLoggedIn = true;
        res.locals.user = req.user;
        
        return checkBanStatus(req, res, next);
    } catch (error) {
        res.cookie('token', '', { expires: new Date(0) });
        return res.redirect('/login');
    }
};

exports.protectApi = async (req, res, next) => {
    let token;
    if (req.cookies.token) {
        token = req.cookies.token;
    } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.headers['x-api-key']) {
        token = req.headers['x-api-key'];
    }

    if (!token) {
        return res.status(401).json({ status: 'error', message: 'Not authorized, no token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (user) {
            if (user.passwordChangedAt) {
                const changedTimestamp = parseInt(user.passwordChangedAt.getTime() / 1000, 10);
                if (decoded.iat < changedTimestamp) {
                    throw new Error('Password changed, token invalid');
                }
            }
            req.user = user;
            if (user.isBanned) return res.status(403).json({ message: 'Account banned.' });
            return next();
        }
    } catch (err) {}

    try {
        const user = await User.findOne({ 'apiKeys.key': token }).select('-password');
        if (user) {
            req.user = user;
            if (user.isBanned) return res.status(403).json({ message: 'Account banned.' });
            return next();
        } else {
            return res.status(401).json({ status: 'error', message: 'Not authorized, token failed.' });
        }
    } catch (error) {
        return res.status(500).json({ status: 'error', message: 'Server error during authentication.' });
    }
};

exports.protectAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return res.status(403).send('Access denied. Admin only.');
};

exports.checkAuthStatus = async (req, res, next) => {
    let token;
    res.locals.isLoggedIn = false;
    res.locals.user = null;

    if (req.cookies.token) {
        token = req.cookies.token;
    }

    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id).select('-password');
            if (user) {
                res.locals.isLoggedIn = true;
                res.locals.user = user;
                if (user.isBanned) {
                    res.locals.isLoggedIn = false;
                    res.locals.user = null;
                }
            }
        } catch (error) {}
    }
    next();
};
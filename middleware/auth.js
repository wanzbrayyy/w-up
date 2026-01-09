const jwt = require('jsonwebtoken');
const User = require('../models/user');

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
        req.user = await User.findById(decoded.id).select('-password');
        if (!req.user) {
            res.cookie('token', '', { expires: new Date(0) });
            return res.redirect('/login');
        }
        res.locals.isLoggedIn = true;
        res.locals.user = req.user;
        next();
    } catch (error) {
        res.cookie('token', '', { expires: new Date(0) });
        return res.redirect('/login');
    }
};

exports.protectApi = async (req, res, next) => {
    let token;
    if (req.cookies.token) {
        token = req.cookies.token;
    }

    if (!token) {
        return res.status(401).json({ status: 'error', message: 'Not authorized, no token provided.' });
    }

    // Coba verifikasi sebagai JWT (untuk sesi browser)
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if (user) {
            req.user = user;
            return next();
        }
    } catch (err) {
        // Jika JWT gagal, jangan langsung error, lanjutkan untuk cek API Key
    }
    
    // Jika JWT gagal, coba verifikasi sebagai API Key
    try {
        const user = await User.findOne({ 'apiKeys.key': token }).select('-password');
        if (user) {
            req.user = user;
            return next();
        } else {
            return res.status(401).json({ status: 'error', message: 'Not authorized, token failed.' });
        }
    } catch (error) {
        return res.status(500).json({ status: 'error', message: 'Server error during authentication.' });
    }
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
            }
        } catch (error) {
            // Token invalid, do nothing
        }
    }
    next();
};
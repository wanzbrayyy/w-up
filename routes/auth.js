const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const router = express.Router();

router.post('/register', async (req, res) => {
    try {
        const { username, password, referralCode } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists.' });
        }

        let referrer = null;
        let bonus = 0;
        if (referralCode) {
            referrer = await User.findOne({ referralCode });
            if (referrer) {
                referrer.storageBonus += 52428800; // +50MB for referrer
                await referrer.save();
                bonus = 52428800; // +50MB for new user
            }
        }

        const user = new User({ username, password, referredBy: referrer?._id, storageBonus: bonus });
        await user.save();
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        user.loginHistory.push({ ip: req.ip, userAgent: req.headers['user-agent'] });
        if (user.loginHistory.length > 10) user.loginHistory.shift();
        await user.save();

        if (user.isTwoFactorEnabled) {
            const tempToken = jwt.sign({ id: user._id, partial: true }, process.env.JWT_SECRET, { expiresIn: '5m' });
            res.cookie('temp_token', tempToken, { httpOnly: true });
            return res.status(200).json({ status: '2fa_required', message: '2FA code required.' });
        }

        const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 86400000 });
        res.status(200).json({ message: 'Logged in successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

router.post('/login/2fa', async (req, res) => {
    const { code } = req.body;
    const tempToken = req.cookies.temp_token;
    if(!tempToken) return res.status(401).json({ message: 'Session expired.' });

    try {
        const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        
        const speakeasy = require('speakeasy');
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret.ascii,
            encoding: 'ascii',
            token: code
        });

        if(verified) {
            const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
            res.clearCookie('temp_token');
            res.cookie('token', token, { httpOnly: true, maxAge: 86400000 });
            res.json({ message: 'Login successful' });
        } else {
            res.status(400).json({ message: 'Invalid 2FA code' });
        }
    } catch(e) {
        res.status(401).json({ message: 'Error verifying 2FA' });
    }
});

router.get('/logout', (req, res) => {
    res.cookie('token', '', { expires: new Date(0) });
    res.redirect('/login');
});

module.exports = router;
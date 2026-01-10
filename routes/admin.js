const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const File = require('../models/file');
const SystemConfig = require('../models/systemConfig');
const auth = require('../middleware/auth');

// Middleware: Harus login & harus Admin
router.use(auth.protectView, auth.protectAdmin);

// Dashboard Admin
router.get('/', async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const fileCount = await File.countDocuments();
        const totalStorage = await File.aggregate([{ $group: { _id: null, total: { $sum: "$size" } } }]);
        const users = await User.find().sort({ createdAt: -1 }).limit(20);
        const config = await SystemConfig.getConfig();

        res.render('admin_dashboard', {
            userCount,
            fileCount,
            totalSize: totalStorage[0] ? totalStorage[0].total : 0,
            users,
            config
        });
    } catch (e) {
        res.status(500).send('Admin Error');
    }
});

// Update System Config (Maintenance, Announcement, Ads)
router.post('/config', async (req, res) => {
    const { maintenanceMode, globalAnnouncement, adsEnabled, adScript } = req.body;
    await SystemConfig.findOneAndUpdate({}, {
        maintenanceMode: maintenanceMode === 'on',
        globalAnnouncement,
        adsEnabled: adsEnabled === 'on',
        adScript
    }, { upsert: true });
    res.redirect('/admin');
});

// User Actions: Ban/Unban & Role
router.post('/users/:id/update', async (req, res) => {
    const { action, value } = req.body;
    const userId = req.params.id;

    if (action === 'ban') {
        await User.findByIdAndUpdate(userId, { isBanned: true, banReason: value || 'Violation of TOS' });
    } else if (action === 'unban') {
        await User.findByIdAndUpdate(userId, { isBanned: false, banReason: null });
    } else if (action === 'role') {
        await User.findByIdAndUpdate(userId, { role: value }); // value = 'admin' or 'user'
    } else if (action === 'verify') {
        await User.findByIdAndUpdate(userId, { isVerified: true });
    }
    
    res.redirect('/admin');
});

// Impersonate User (Login as User)
router.get('/impersonate/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).send('User not found');

    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');
});

module.exports = router;
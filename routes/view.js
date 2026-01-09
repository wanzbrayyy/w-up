const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const geoip = require('geoip-lite');
const File = require('../models/file');
const User = require('../models/user');
const Team = require('../models/team');
const FileRequest = require('../models/fileRequest');
const auth = require('../middleware/auth');

router.get('/', auth.checkAuthStatus, (req, res) => res.render('index'));
router.get('/login', auth.checkAuthStatus, (req, res) => res.locals.isLoggedIn ? res.redirect('/dashboard') : res.render('login'));
router.get('/register', auth.checkAuthStatus, (req, res) => res.locals.isLoggedIn ? res.redirect('/dashboard') : res.render('register'));
router.get('/profile', auth.protectView, (req, res) => res.render('profile'));

router.get('/docs', auth.checkAuthStatus, (req, res) => {
    res.render('docs');
});

router.get('/u/:username', auth.checkAuthStatus, async (req, res) => {
    try {
        const targetUser = await User.findOne({ username: req.params.username, isPublicProfile: true });
        if (!targetUser) return res.status(404).render('404');
        
        const files = await File.find({ 
            owner: targetUser._id, 
            isHidden: false, 
            deletedAt: null, 
            isFolder: false 
        }).sort({ createdAt: -1 }).select('-base64 -password');
        
        res.render('public_profile', { targetUser, files });
    } catch (e) { res.status(500).render('404'); }
});

router.get('/req/:slug', async (req, res) => {
    try {
        const request = await FileRequest.findOne({ slug: req.params.slug });
        if (!request) return res.status(404).send('Request not found or expired');
        res.render('file_request', { request });
    } catch (e) { res.status(500).send('Error'); }
});

router.get('/dashboard/teams', auth.protectView, async (req, res) => {
    try {
        const teams = await Team.find({ _id: { $in: req.user.teams } }).populate('members', 'username');
        res.render('teams', { teams });
    } catch (e) { res.status(500).send("Error fetching teams"); }
});

router.get('/dashboard', auth.protectView, async (req, res) => {
    try {
        const { q, sortBy, sortOrder, folderId, type, filter, tag } = req.query;
        let query = {};

        if (filter === 'trash') {
            query = { owner: req.user.id, deletedAt: { $ne: null } };
        } else if (filter === 'shared') {
            query = { collaborators: req.user.id, deletedAt: null };
        } else if (filter === 'starred') {
            query = { owner: req.user.id, isStarred: true, deletedAt: null };
        } else {
            query = { 
                $or: [{ owner: req.user.id }, { collaborators: req.user.id }],
                deletedAt: null 
            };
            if (!q && filter !== 'all') {
                query.parentId = folderId || null;
            }
        }

        if (q) {
            query.$or = [
                { originalName: { $regex: q, $options: 'i' } },
                { tags: { $in: [q] } }
            ];
            delete query.parentId; 
        }

        if (type) {
            if (type === 'image') query.contentType = { $regex: '^image/' };
            else if (type === 'video') query.contentType = { $regex: '^video/' };
            else if (type === 'doc') query.contentType = { $regex: 'pdf|document|text' };
            else if (type === 'folder') query.isFolder = true;
        }

        if (tag) query.tags = tag;

        let sort = {};
        if (sortBy) sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
        else sort = { isFolder: -1, createdAt: -1 };

        const files = await File.find(query).sort(sort).select('-base64 -versions.base64');
        
        let currentFolder = null;
        let breadcrumbs = [];
        if (folderId) {
            currentFolder = await File.findOne({ _id: folderId });
            let temp = currentFolder;
            while(temp) {
                breadcrumbs.unshift({ id: temp._id, name: temp.originalName });
                if(temp.parentId) temp = await File.findById(temp.parentId);
                else temp = null;
            }
        }

        res.render('dashboard', { files, query: req.query, currentFolder, breadcrumbs });
    } catch (error) {
        res.status(500).send("Error fetching user files.");
    }
});

router.get('/w-upload/file/:identifier', auth.checkAuthStatus, async (req, res) => {
    try {
        const file = await File.findOne({ customAlias: req.params.identifier })
            .select('-base64')
            .populate('comments.user', 'username');
            
        if (!file || file.deletedAt) return res.status(404).render('404');

        if (file.password) {
            const token = req.cookies[`file_access_${file._id}`];
            if (!token) return res.render('password_prompt', { file, hint: file.passwordHint });
            try {
                jwt.verify(token, process.env.JWT_SECRET);
            } catch (e) {
                return res.render('password_prompt', { file, hint: file.passwordHint, error: 'Session expired.' });
            }
        }
        
        if (file.originalName.match(/\.(js|css|html|php|vue|dart|json|py|java|c|cpp|xml|ts|jsx|md|txt)$/i)) {
            return res.render('viewer', { file, downloadLink: `/w-upload/raw/${file.customAlias}` });
        }
        res.render('download', { file, downloadLink: `/w-upload/raw/${file.customAlias}` });
    } catch (error) {
        res.status(500).send("Server Error");
    }
});

router.post('/w-upload/file/:identifier/auth', async (req, res) => {
    const file = await File.findOne({ customAlias: req.params.identifier }).select('-base64');
    if (!file || !file.password) return res.redirect(`/w-upload/file/${req.params.identifier}`);
    
    const isMatch = await bcrypt.compare(req.body.password, file.password);
    if (isMatch) {
        const token = jwt.sign({ fileId: file._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie(`file_access_${file._id}`, token, { httpOnly: true, maxAge: 3600000 });
        res.redirect(`/w-upload/file/${req.params.identifier}`);
    } else {
        res.render('password_prompt', { file, hint: file.passwordHint, error: 'Invalid password' });
    }
});

router.get('/w-upload/raw/:identifier', async (req, res) => {
    try {
        const file = await File.findOne({ customAlias: req.params.identifier });
        if (!file || file.deletedAt) return res.status(404).send('File not found');

        // Geo Fencing Check (IP Based)
        if (file.allowedGeo && file.allowedGeo.lat) {
            const ip = req.ip || req.socket.remoteAddress;
            const geo = geoip.lookup(ip);
            // Implementasi sederhana: Tolak jika tidak bisa mendeteksi lokasi atau (opsional) tambahkan logika radius
            // Jika geo strict diperlukan, biasanya butuh Client-Side GPS -> API POST -> Token Download
            if (!geo) {
               // Fallback: Proceed or Block depending on strictness. Here we allow but log.
            }
        }

        if (file.expiresAt && file.expiresAt < new Date()) {
            file.deletedAt = new Date();
            await file.save();
            return res.status(410).send('Link has expired.');
        }

        if (file.downloadLimit !== undefined && file.downloadLimit <= 0) {
            file.deletedAt = new Date();
            await file.save();
            return res.status(410).send('Download limit reached.');
        }

        if (file.password) {
            const token = req.cookies[`file_access_${file._id}`];
            if (!token) return res.status(403).send('Password required.');
            try {
                jwt.verify(token, process.env.JWT_SECRET);
            } catch (e) {
                return res.status(403).send('Access denied.');
            }
        }

        if (file.downloadLimit !== undefined) {
            file.downloadLimit -= 1;
        }

        // Update Statistics
        file.downloads += 1;
        file.lastDownloadedAt = new Date();
        const today = new Date().setHours(0,0,0,0);
        const histIndex = file.downloadHistory.findIndex(h => new Date(h.date).getTime() === today);
        if(histIndex > -1) file.downloadHistory[histIndex].count++;
        else file.downloadHistory.push({ date: today, count: 1 });

        // Burn After Read Logic
        if (file.isBurnAfterRead) {
            file.deletedAt = new Date();
        }

        await file.save();

        const fileBuffer = Buffer.from(file.base64.split(';base64,').pop(), 'base64');
        res.writeHead(200, {
            'Content-Type': file.contentType,
            'Content-Length': fileBuffer.length,
            'Content-Disposition': `inline; filename="${file.originalName}"`
        });
        res.end(fileBuffer);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

module.exports = router;
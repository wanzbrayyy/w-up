const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const File = require('../models/file');
const User = require('../models/user');
const Team = require('../models/team');
const FileRequest = require('../models/fileRequest');
const auth = require('../middleware/auth');
const { r2, GetObjectCommand, DeleteObjectCommand } = require('../utils/r2');

// --- ROUTES AUTH VIEW ---

router.get('/', auth.checkAuthStatus, (req, res) => res.render('index'));

router.get('/login', auth.checkAuthStatus, (req, res) => 
    res.locals.isLoggedIn ? res.redirect('/dashboard') : res.render('login')
);

router.get('/register', auth.checkAuthStatus, (req, res) => 
    res.locals.isLoggedIn ? res.redirect('/dashboard') : res.render('register')
);

// FIX: Menambahkan Route Logout di sini agar bisa diakses via /logout
router.get('/logout', async (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    
    // Hapus sesi dari database jika ada refresh token
    if (refreshToken) {
        try {
            const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
            await User.updateOne({ _id: decoded.id }, { $pull: { sessions: { refreshToken } } });
        } catch(e) {
            // Token invalid atau expired, abaikan error saat logout
        }
    }

    // Hapus semua cookies
    res.clearCookie('token');
    res.clearCookie('refresh_token');
    res.clearCookie('temp_token');

    // Opsional: Hapus cookie akses file jika ada
    const cookies = req.cookies;
    for (const cookieName in cookies) {
        if (cookieName.startsWith('file_access_')) {
            res.clearCookie(cookieName);
        }
    }

    res.redirect('/login');
});

// --- ROUTES DASHBOARD & UTILS ---

router.get('/profile', auth.protectView, (req, res) => {
    const currentRefreshToken = req.cookies.refresh_token || '';
    res.render('profile', { currentRefreshToken });
});

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

router.get('/req/:slug', auth.checkAuthStatus, async (req, res) => {
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

router.get('/dashboard/affiliate', auth.protectView, async (req, res) => {
    const referrals = await User.find({ referredBy: req.user.id }).select('username createdAt isVerified plan');
    res.render('affiliate', { referrals });
});

router.post('/billing/upgrade', auth.protectView, async (req, res) => {
    req.user.plan = 'pro';
    req.user.storageLimit = 50 * 1024 * 1024 * 1024;
    req.user.subscriptionExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); 
    await req.user.save();
    res.json({ message: 'Upgraded to PRO successfully!' });
});

router.get('/dashboard', auth.protectView, async (req, res) => {
    try {
        const { q, sortBy, sortOrder, folderId, type, filter, tag } = req.query;
        let query = {};
        let currentFolder = null;
        let breadcrumbs = [];

        if (folderId) {
            currentFolder = await File.findOne({ 
                _id: folderId,
                $or: [{ owner: req.user.id }, { collaborators: req.user.id }]
            });

            if (!currentFolder) {
                return res.status(404).send("Folder not found or access denied.");
            }

            query = { parentId: folderId, deletedAt: null };

            let temp = currentFolder;
            while(temp) {
                breadcrumbs.unshift({ id: temp._id, name: temp.originalName });
                if(temp.parentId) temp = await File.findById(temp.parentId);
                else temp = null;
            }
        } else {
            if (filter === 'trash') {
                query = { owner: req.user.id, deletedAt: { $ne: null } };
            } else if (filter === 'shared') {
                query = { collaborators: req.user.id, deletedAt: null };
            } else if (filter === 'starred') {
                query = { owner: req.user.id, isStarred: true, deletedAt: null };
            } else {
                query = { 
                    owner: req.user.id,
                    parentId: null, 
                    deletedAt: null 
                };
            }
        }

        if (q) {
            query = {
                $or: [{ owner: req.user.id }, { collaborators: req.user.id }],
                deletedAt: null,
                $or: [
                    { originalName: { $regex: q, $options: 'i' } },
                    { tags: { $in: [q] } }
                ]
            };
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
        
        const stats = await File.aggregate([
            { $match: { owner: req.user._id, deletedAt: null } },
            { $group: { _id: null, totalSize: { $sum: "$size" } } }
        ]);
        const currentUsage = stats.length > 0 ? stats[0].totalSize : 0;
        req.user.storageUsed = currentUsage;
        await req.user.save();

        res.render('dashboard', { files, query: req.query, currentFolder, breadcrumbs });
    } catch (error) {
        console.error(error);
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
            try { jwt.verify(token, process.env.JWT_SECRET); } 
            catch (e) { return res.render('password_prompt', { file, hint: file.passwordHint, error: 'Session expired.' }); }
        }
        
        const downloadLink = file.isFolder ? `/api/files/${file._id}/zip` : `/w-upload/raw/${file.customAlias}`;
        const fileExtension = path.extname(file.originalName).toLowerCase();
        const isOwner = req.user && file.owner.equals(req.user._id);

        // Logic routing ke viewer yang tepat
        if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(fileExtension) && isOwner) {
            return res.render('editor_image', { file, downloadLink });
        }
        if (fileExtension === '.pdf' && isOwner) {
            return res.render('editor_pdf', { file, rawLink: downloadLink });
        }
        if (fileExtension === '.md' && isOwner) {
            return res.render('editor_markdown', { file, rawLink: downloadLink });
        }
        if (['.js', '.css', '.html', '.py', '.java', '.c', '.cpp', '.xml', '.ts', '.jsx', '.json', '.sql', '.rb', '.go'].includes(fileExtension)) {
            return res.render('viewer_code', { file, rawLink: downloadLink, ext: fileExtension.substring(1) });
        }
        if (['.zip', '.rar'].includes(fileExtension)) {
             return res.render('viewer_archive', { file, downloadLink });
        }

        res.render('download', { file, downloadLink });
    } catch (error) {
        console.error(error);
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
        
        if (!file) return res.status(404).send('File not found in database.');
        if (file.deletedAt) return res.status(410).send('File has been deleted.');
        if (file.isFolder) return res.status(400).send('Cannot raw download a folder. Use zip.');

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

        if (file.downloadLimit !== undefined) file.downloadLimit -= 1;
        file.downloads += 1;
        file.lastDownloadedAt = new Date();
        const today = new Date().setHours(0,0,0,0);
        const histIndex = file.downloadHistory.findIndex(h => new Date(h.date).getTime() === today);
        if(histIndex > -1) file.downloadHistory[histIndex].count++;
        else file.downloadHistory.push({ date: today, count: 1 });

        if (file.isBurnAfterRead) file.deletedAt = new Date();
        await file.save();

        if (file.storageType === 'r2' && file.r2Key) {
            try {
                const command = new GetObjectCommand({
                    Bucket: process.env.R2_BUCKET_NAME,
                    Key: file.r2Key
                });
                
                const response = await r2.send(command);

                res.setHeader('Content-Type', file.contentType);
                res.setHeader('Content-Length', file.size);
                res.setHeader('Content-Disposition', `inline; filename="${file.originalName}"`);

                response.Body.pipe(res);

                if (file.isBurnAfterRead) {
                    await r2.send(new DeleteObjectCommand({ 
                        Bucket: process.env.R2_BUCKET_NAME, 
                        Key: file.r2Key 
                    }));
                }
            } catch (r2Error) {
                console.error("Cloudflare R2 Error:", r2Error);
                return res.status(500).send("Error retrieving file from Cloud Storage.");
            }
        } 
        else if (file.base64) {
            const fileBuffer = Buffer.from(file.base64.split(';base64,').pop(), 'base64');
            res.writeHead(200, {
                'Content-Type': file.contentType,
                'Content-Length': fileBuffer.length,
                'Content-Disposition': `inline; filename="${file.originalName}"`
            });
            res.end(fileBuffer);
        } 
        else {
            return res.status(500).send("File content corrupted or missing.");
        }

    } catch (error) {
        console.error("General Download Error:", error);
        res.status(500).send('Server Internal Error during download.');
    }
});

module.exports = router;
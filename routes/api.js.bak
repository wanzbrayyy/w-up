const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jimp = require('jimp');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const axios = require('axios');
const nodemailer = require('nodemailer');
const archiver = require('archiver');
//const { v4: uuidv4 } = require('uuid');
const File = require('../models/file');
const User = require('../models/user');
const Team = require('../models/team');
const { r2, PutObjectCommand } = require('../utils/r2'); 
const FileRequest = require('../models/fileRequest');
const UploadSession = require('../models/uploadSession');
const auth = require('../middleware/auth');
const {
    passkeyConfig,
    generateRegistrationOptions,
    verifyRegistrationResponse,
} = require('../utils/passkey'); 

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendEmail(to, subject, htmlContent) {
    try {
        const mailOptions = {
            from: `"w upload" <${process.env.EMAIL_USER}>`,
            to: to,
            subject: subject,
            html: htmlContent
        };
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        return false;
    }
}

function sanitizeFilename(name) {
    return name.replace(/\0/g, '')
        .replace(/(\.\.(\/|\\|$))+/g, '')
        .replace(/[^\w\s.\-()]/gi, '_')
        .trim();
}

function validateMagicBytes(buffer, contentType) {
    const hex = buffer.toString('hex', 0, 8).toUpperCase();
    
    if (hex.startsWith('4D5A')) return false; 

    const signatures = {
        'image/jpeg': ['FFD8FF'],
        'image/png': ['89504E47'],
        'image/gif': ['47494638'],
        'application/pdf': ['25504446'],
        'application/zip': ['504B0304'],
        'application/x-rar-compressed': ['52617221']
    };

    if (signatures[contentType]) {
        return signatures[contentType].some(sig => hex.startsWith(sig));
    }

    return true; 
}

router.post('/folder', auth.protectApi, async (req, res) => {
    try {
        const { name, parentId } = req.body;
        const cleanName = sanitizeFilename(name); 
        
        const newFolder = new File({
            originalName: cleanName,
            customAlias: `folder_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
            contentType: 'application/vnd.google-apps.folder',
            size: 0,
            base64: '',
            owner: req.user.id,
            isFolder: true,
            parentId: parentId || null
        });
        await newFolder.save();
        res.status(201).json({ status: 'success', folder: newFolder });
    } catch (error) {
        res.status(500).json({ message: 'Error creating folder' });
    }
});
// --- UPLOAD LOGIC (Diperbaiki: Menggunakan crypto.randomUUID) ---
router.post('/upload', async (req, res) => {
    try {
        let user = null;
        if (req.headers.authorization || req.cookies.token) {
            await new Promise((resolve) => {
                auth.protectApi(req, res, () => { 
                    if(req.user) user = req.user; 
                    resolve(); 
                });
            });
        }

        if (!user && req.body.fileRequestSlug) {
             const reqObj = await FileRequest.findOne({ slug: req.body.fileRequestSlug });
             if (reqObj) {
                 user = { id: reqObj.owner };
                 req.body.parentId = reqObj.destinationFolder; 
             }
        } 
        else if (!user && process.env.ALLOW_GUEST_UPLOAD !== 'true') {
             return res.status(401).json({ message: 'Authentication required.' });
        }

        let { filename, contentType, base64, watermarkText, parentId, description, tags, hidden, expires, limit, password, hint, geo, burn, customAlias } = req.body;
        
        // 1. Convert Base64 ke Buffer
        let buffer = Buffer.from(base64.split(',')[1], 'base64');
        
        // 2. Magic Bytes Validation
        // Pastikan fungsi validateMagicBytes ada di file ini atau diimport
        // if (!validateMagicBytes(buffer, contentType)) { ... } 

        // 3. Watermark Process
        if (contentType.startsWith('image/') && watermarkText) {
            const image = await jimp.read(buffer);
            const font = await jimp.loadFont(jimp.FONT_SANS_32_WHITE);
            image.print(font, 10, image.bitmap.height - 40, watermarkText);
            buffer = await image.getBufferAsync(jimp.MIME_PNG); 
        }

        const hash = crypto.createHash('md5').update(buffer).digest('hex');
        const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

        // 4. Duplicate Check
        if (user) {
            const duplicate = await File.findOne({ owner: user.id, md5Hash: hash, deletedAt: null });
            if (duplicate) {
                return res.status(200).json({ 
                    status: 'success', 
                    message: 'Duplicate file detected', 
                    url: `${req.protocol}://${req.get('host')}/w-upload/file/${duplicate.customAlias}`, 
                    filename: duplicate.customAlias 
                });
            }
        }

        let finalAlias = customAlias || filename; // Menggunakan filename asli jika customAlias kosong
        // Sanitasi filename agar aman (hapus karakter aneh)
        finalAlias = finalAlias.replace(/[^a-zA-Z0-9._-]/g, '_');

        let counter = 1;
        while (await File.findOne({ customAlias: finalAlias })) {
            const ext = path.extname(filename);
            const name = path.basename(filename, ext).replace(/[^a-zA-Z0-9._-]/g, '_');
            finalAlias = `${name}_${counter}${ext}`;
            counter++;
        }

        // 5. UPLOAD TO R2
        // PERBAIKAN DI SINI: Menggunakan crypto.randomUUID() menggantikan uuidv4()
        const r2Key = `${user ? user.id : 'guest'}/${Date.now()}_${crypto.randomUUID()}_${finalAlias}`;
        
        const { r2, PutObjectCommand } = require('../utils/r2'); // Pastikan import ini ada/sesuai path
        await r2.send(new PutObjectCommand({
            Bucket: process.env.R2_BUCKET_NAME,
            Key: r2Key,
            Body: buffer,
            ContentType: contentType
        }));

        // 6. Save Metadata
        const newFile = new File({
            originalName: filename, 
            customAlias: finalAlias, 
            contentType, 
            size: buffer.length, 
            storageType: 'r2',
            r2Key: r2Key,
            owner: user ? user.id : null,
            parentId: parentId || null,
            description,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            isHidden: hidden === 'true',
            md5Hash: hash,
            sha256Hash: sha256,
            isBurnAfterRead: burn === 'true',
            passwordHint: hint,
            allowedGeo: geo ? JSON.parse(geo) : undefined,
            expiresAt: expires ? new Date(Date.now() + expires * 3600000) : undefined,
            downloadLimit: limit ? parseInt(limit) : undefined
        });

        if (password) newFile.password = await bcrypt.hash(password, 10);

        await newFile.save();
        res.status(201).json({ status: 'success', url: `${req.protocol}://${req.get('host')}/w-upload/file/${finalAlias}`, filename: finalAlias });
    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ status: 'error', message: 'Upload failed' });
    }
});

router.post('/upload/remote', auth.protectApi, async (req, res) => {
    try {
        const { url, parentId } = req.body;
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        const contentType = response.headers['content-type'];
        const buffer = Buffer.from(response.data, 'binary');
        
        if (!validateMagicBytes(buffer, contentType)) {
            return res.status(400).json({ message: 'Remote file type validation failed.' });
        }

        const base64 = `data:${contentType};base64,${buffer.toString('base64')}`;
        let filename = path.basename(url) || `remote_${Date.now()}`;
        filename = sanitizeFilename(filename);
        
        const newFile = new File({
            originalName: filename,
            customAlias: `remote_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
            contentType,
            size: buffer.length,
            base64,
            owner: req.user.id,
            parentId: parentId || null,
            md5Hash: crypto.createHash('md5').update(buffer).digest('hex'),
            sha256Hash: crypto.createHash('sha256').update(buffer).digest('hex')
        });
        await newFile.save();
        res.status(201).json({ message: 'Remote upload success' });
    } catch (error) {
        res.status(500).json({ message: 'Remote upload failed' });
    }
});

router.post('/upload/chunk/init', auth.protectApi, async (req, res) => {
    const { filename, totalSize } = req.body;
    const cleanName = sanitizeFilename(filename);
    const sessionId = crypto.randomBytes(16).toString('hex');
    const session = new UploadSession({ sessionId, owner: req.user.id, filename: cleanName, totalSize });
    await session.save();
    res.json({ sessionId });
});

router.post('/upload/chunk', auth.protectApi, async (req, res) => {
    const { sessionId, chunkIndex, base64Chunk } = req.body;
    const session = await UploadSession.findOne({ sessionId, owner: req.user.id });
    if (!session) return res.status(404).json({ message: 'Session not found' });
    
    session.chunks.push({ index: chunkIndex, data: base64Chunk });
    await session.save();
    res.json({ message: 'Chunk received' });
});

router.post('/upload/chunk/finalize', auth.protectApi, async (req, res) => {
    const { sessionId, parentId } = req.body;
    const session = await UploadSession.findOne({ sessionId, owner: req.user.id });
    if (!session) return res.status(404).json({ message: 'Session not found' });

    session.chunks.sort((a, b) => a.index - b.index);
    const fullBase64 = session.chunks.map(c => c.data.split(',')[1]).join('');
    
    const buffer = Buffer.from(fullBase64, 'base64');
    if (!validateMagicBytes(buffer, 'application/octet-stream')) { 
         await UploadSession.deleteOne({ _id: session._id });
         return res.status(400).json({ message: 'File rejected due to security policy.' });
    }

    const finalBase64 = `data:application/octet-stream;base64,${fullBase64}`;
    const fileSize = (fullBase64.length * (3/4)); 

    const newFile = new File({
        originalName: sanitizeFilename(session.filename),
        customAlias: `chunk_${Date.now()}_${sanitizeFilename(session.filename)}`,
        contentType: 'application/octet-stream', 
        size: fileSize,
        base64: finalBase64,
        owner: req.user.id,
        parentId: parentId || null,
        md5Hash: crypto.createHash('md5').update(buffer).digest('hex'),
        sha256Hash: crypto.createHash('sha256').update(buffer).digest('hex')
    });

    await newFile.save();
    await UploadSession.deleteOne({ _id: session._id });
    res.status(201).json({ message: 'File assembled successfully' });
});

router.put('/files/:id/rename', auth.protectApi, async (req, res) => {
    try {
        const cleanName = sanitizeFilename(req.body.newName);
        await File.findOneAndUpdate({ _id: req.params.id, owner: req.user.id }, { originalName: cleanName });
        res.json({ message: 'Renamed successfully' });
    } catch (e) { res.status(500).json({ message: 'Error' }); }
});

router.put('/files/:id/meta', auth.protectApi, async (req, res) => {
    try {
        const { description, tags, isHidden } = req.body;
        const update = {};
        if (description !== undefined) update.description = description;
        if (tags !== undefined) update.tags = tags.split(',').map(t => sanitizeFilename(t.trim()));
        if (isHidden !== undefined) update.isHidden = isHidden;
        await File.findOneAndUpdate({ _id: req.params.id, owner: req.user.id }, update);
        res.json({ message: 'Metadata updated' });
    } catch (e) { res.status(500).json({ message: 'Error' }); }
});

router.put('/files/:id/protect', auth.protectApi, async (req, res) => {
    try {
        const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
        if (!file) return res.status(404).json({ message: 'File not found.' });

        const { password, expires, limit, hint } = req.body;
        if (password) file.password = await bcrypt.hash(password, 10);
        else if (req.body.removePassword) file.password = undefined;

        if (hint) file.passwordHint = hint;
        if (expires) file.expiresAt = new Date(Date.now() + expires * 60 * 60 * 1000);
        if (limit) file.downloadLimit = parseInt(limit, 10);

        await file.save();
        res.status(200).json({ message: 'Protection updated.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error.' });
    }
});

router.delete('/files/:id', auth.protectApi, async(req, res) => {
    await File.findOneAndUpdate({_id: req.params.id, owner: req.user.id}, {deletedAt: new Date()});
    res.json({message:'File moved to trash'});
});

router.post('/files/bulk', auth.protectApi, async (req, res) => {
    const { fileIds, action, targetFolderId } = req.body;
    if (!fileIds || !Array.isArray(fileIds)) return res.status(400).json({ message: 'Invalid files' });

    try {
        const query = { _id: { $in: fileIds }, owner: req.user.id };
        if (action === 'delete') await File.updateMany(query, { deletedAt: new Date() });
        else if (action === 'restore') await File.updateMany(query, { deletedAt: null });
        else if (action === 'move') await File.updateMany(query, { parentId: targetFolderId || null });
        else if (action === 'star') await File.updateMany(query, { isStarred: true });
        else if (action === 'unstar') await File.updateMany(query, { isStarred: false });
        
        res.json({ message: 'Bulk action completed' });
    } catch (e) {
        res.status(500).json({ message: 'Bulk action failed' });
    }
});

router.delete('/trash/empty', auth.protectApi, async (req, res) => {
    await File.deleteMany({ owner: req.user.id, deletedAt: { $ne: null } });
    res.json({ message: 'Trash emptied' });
});

router.post('/files/:id/collaborator', auth.protectApi, async (req, res) => {
    const { username } = req.body;
    const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
    if (!file) return res.status(404).json({ message: 'File not found' });
    
    const collabUser = await User.findOne({ username });
    if (!collabUser) return res.status(404).json({ message: 'User not found' });
    
    if (!file.collaborators.includes(collabUser._id)) {
        file.collaborators.push(collabUser._id);
        await file.save();
    }
    
    if (collabUser.email) {
        const link = `${req.protocol}://${req.get('host')}/dashboard?folderId=${file._id}`; 
        const html = `<h3>You've been invited to collaborate!</h3>
                      <p>${req.user.username} has added you to the folder/file: <b>${file.originalName}</b></p>
                      <p><a href="${link}">Open Folder</a></p>`;
        await sendEmail(collabUser.email, `Collaboration Invite: ${file.originalName}`, html);
    }

    res.json({ message: 'Collaborator added and notified' });
});

router.post('/files/:id/email-share', auth.protectApi, async (req, res) => {
    const { email } = req.body;
    const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
    if (!file) return res.status(404).json({ message: 'File not found' });
    
    const existingUser = await User.findOne({ email });
    if (existingUser && !file.collaborators.includes(existingUser._id)) {
        file.collaborators.push(existingUser._id);
        await file.save();
    }

    let link;
    if (file.isFolder) {
        link = `${req.protocol}://${req.get('host')}/dashboard?folderId=${file._id}`; 
    } else {
        link = `${req.protocol}://${req.get('host')}/w-upload/file/${file.customAlias}`;
    }

    const htmlContent = `
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
            <h2 style="color: #4f46e5;">File Shared with You</h2>
            <p><strong>${req.user.username}</strong> has shared a ${file.isFolder ? 'folder' : 'file'} with you.</p>
            <div style="margin: 20px 0; padding: 15px; background: #f9fafb; border-radius: 5px;">
                <p style="margin: 0; font-weight: bold;">${file.originalName}</p>
                <p style="margin: 5px 0 0 0; color: #666; font-size: 0.9em;">Size: ${(file.size / 1024 / 1024).toFixed(2)} MB</p>
            </div>
            <a href="${link}" style="display: inline-block; background: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Open ${file.isFolder ? 'Folder' : 'File'}</a>
            <p style="font-size: 0.8em; color: #888; margin-top: 20px;">If the button doesn't work, copy this link: <br>${link}</p>
        </div>
    `;

    await sendEmail(email, `${req.user.username} shared "${file.originalName}"`, htmlContent);
    res.json({ message: 'Email sent successfully' });
});

router.get('/files/:id/zip', auth.protectApi, async (req, res) => {
    try {
        const folderId = req.params.id;
        const folder = await File.findOne({ 
            _id: folderId, 
            $or: [{ owner: req.user.id }, { collaborators: req.user.id }] 
        });

        if (!folder || !folder.isFolder) return res.status(404).send('Folder not found or access denied');

        const files = await File.find({ parentId: folderId, isFolder: false, deletedAt: null });

        const archive = archiver('zip', { zlib: { level: 9 } });

        res.attachment(`${folder.originalName}.zip`);
        archive.pipe(res);

        for (const file of files) {
            if (file.base64) {
                const base64Data = file.base64.split(';base64,').pop();
                const buffer = Buffer.from(base64Data, 'base64');
                archive.append(buffer, { name: file.originalName });
            }
        }

        await archive.finalize();
    } catch (e) {
        console.error(e);
        res.status(500).send('Error creating zip');
    }
});

router.post('/files/zip', auth.protectApi, async (req, res) => {
    try {
        const { fileIds } = req.body;
        if (!fileIds || !Array.isArray(fileIds)) return res.status(400).send('Invalid files');

        const files = await File.find({ 
            _id: { $in: fileIds }, 
            $or: [{ owner: req.user.id }, { collaborators: req.user.id }],
            isFolder: false 
        });

        const archive = archiver('zip', { zlib: { level: 9 } });

        res.attachment('files.zip');
        archive.pipe(res);

        for (const file of files) {
            if (file.base64) {
                const base64Data = file.base64.split(';base64,').pop();
                const buffer = Buffer.from(base64Data, 'base64');
                archive.append(buffer, { name: file.originalName });
            }
        }

        await archive.finalize();
    } catch (e) {
        res.status(500).send('Error generating zip');
    }
});

router.post('/files/:alias/comment', auth.protectApi, async (req, res) => {
    const { text } = req.body;
    const file = await File.findOne({ customAlias: req.params.alias });
    if (!file) return res.status(404).json({ message: 'File not found' });
    
    file.comments.push({ user: req.user.id, username: req.user.username, text });
    await file.save();
    res.json({ message: 'Comment added', comment: file.comments[file.comments.length-1] });
});

router.post('/files/:alias/react', auth.protectApi, async (req, res) => {
    const { type } = req.body;
    const file = await File.findOne({ customAlias: req.params.alias });
    if (!file) return res.status(404).json({ message: 'File not found' });

    const userId = req.user.id;
    if (!file.reactions) file.reactions = { like: [], love: [] };
    
    const list = file.reactions[type];
    const idx = list.indexOf(userId);
    if (idx === -1) list.push(userId); else list.splice(idx, 1);
    
    await file.save();
    res.json({ message: 'Reaction updated', counts: { like: file.reactions.like.length, love: file.reactions.love.length } });
});

router.post('/teams', auth.protectApi, async (req, res) => {
    const { name } = req.body;
    const cleanName = sanitizeFilename(name);
    const team = new Team({ name: cleanName, owner: req.user.id, members: [req.user.id] });
    await team.save();
    req.user.teams.push(team._id);
    await req.user.save();
    res.status(201).json({ message: 'Team created', team });
});

router.post('/teams/:id/add', auth.protectApi, async (req, res) => {
    const { username } = req.body;
    const team = await Team.findOne({ _id: req.params.id, owner: req.user.id });
    if (!team) return res.status(404).json({ message: 'Team not found' });
    
    const member = await User.findOne({ username });
    if (!member) return res.status(404).json({ message: 'User not found' });
    
    if (!team.members.includes(member._id)) {
        team.members.push(member._id);
        await team.save();
        member.teams.push(team._id);
        await member.save();
    }
    res.json({ message: 'Member added' });
});

router.post('/file-requests', auth.protectApi, async (req, res) => {
    const { v4: uuidv4 } = await import('uuid');
    const { label, folderId } = req.body;
    const slug = uuidv4().substring(0, 8);
    const reqFile = new FileRequest({
        owner: req.user.id,
        slug,
        label: sanitizeFilename(label),
        destinationFolder: folderId || null
    });
    await reqFile.save();
    res.status(201).json({ link: `${req.protocol}://${req.get('host')}/req/${slug}` });
});

router.post('/files/:alias/request-access', auth.protectApi, async (req, res) => {
    const file = await File.findOne({ customAlias: req.params.alias });
    if (!file) return res.status(404).json({ message: 'File not found' });
    
    if (file.accessRequests.some(r => r.user.equals(req.user.id))) {
        return res.status(400).json({ message: 'Request already sent' });
    }
    file.accessRequests.push({ user: req.user.id });
    await file.save();
    res.json({ message: 'Access requested' });
});

router.put('/files/:id/access/:reqId', auth.protectApi, async (req, res) => {
    const { status } = req.body;
    const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
    const reqItem = file.accessRequests.id(req.params.reqId);
    
    if (!reqItem) return res.status(404).json({ message: 'Request not found' });
    reqItem.status = status;
    
    if (status === 'approved') file.collaborators.push(reqItem.user);
    await file.save();
    res.json({ message: `Request ${status}` });
});

router.put('/profile/settings', auth.protectApi, async (req, res) => {
    const { isPublicProfile, publicBio } = req.body;
    req.user.isPublicProfile = isPublicProfile;
    req.user.publicBio = publicBio;
    await req.user.save();
    res.json({ message: 'Profile updated' });
});

router.post('/profile/2fa/setup', auth.protectApi, async (req, res) => {
    const secret = speakeasy.generateSecret({ name: `w-upload (${req.user.username})` });
    req.user.twoFactorSecret = secret;
    await req.user.save();
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        res.json({ qrCodeUrl: data_url, secret: secret.ascii });
    });
});

router.post('/profile/2fa/verify', auth.protectApi, async (req, res) => {
    const { token } = req.body;
    const verified = speakeasy.totp.verify({
        secret: req.user.twoFactorSecret.ascii,
        encoding: 'ascii',
        token
    });
    if (verified) {
        req.user.isTwoFactorEnabled = true;
        await req.user.save();
        res.status(200).json({ message: '2FA enabled.' });
    } else {
        res.status(400).json({ message: 'Invalid token.' });
    }
});

router.post('/profile/api-key', auth.protectApi, async (req, res) => {
    const { label } = req.body;
    const key = `wu_${crypto.randomBytes(24).toString('hex')}`;
    req.user.apiKeys.push({ key, label });
    await req.user.save();
    res.status(201).json({ message: 'API Key generated.', key });
});

router.get('/profile/devices', auth.protectApi, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json({ sessions: user.sessions });
});

router.delete('/profile/devices/:deviceId', auth.protectApi, async (req, res) => {
    await User.updateOne(
        { _id: req.user.id },
        { $pull: { sessions: { deviceId: req.params.deviceId } } }
    );
    res.json({ message: 'Device logged out.' });
});

router.delete('/profile/devices', auth.protectApi, async (req, res) => {
    const currentToken = req.cookies.refresh_token; 
    await User.updateOne(
        { _id: req.user.id },
        { $pull: { sessions: { refreshToken: { $ne: currentToken } } } }
    );
    res.json({ message: 'All other devices logged out.' });
});

router.post('/files/:id/import', auth.protectApi, async (req, res) => {
    try {
        const originalFile = await File.findOne({ _id: req.params.id });
        if (!originalFile || originalFile.deletedAt) return res.status(404).json({ message: 'File not found' });

        const newAlias = `${path.basename(originalFile.originalName, path.extname(originalFile.originalName))}_imported_${Date.now()}${path.extname(originalFile.originalName)}`;
        
        const newFile = new File({
            originalName: originalFile.originalName,
            customAlias: newAlias,
            contentType: originalFile.contentType,
            size: originalFile.size,
            base64: originalFile.base64,
            owner: req.user.id,
            md5Hash: originalFile.md5Hash,
            sha256Hash: originalFile.sha256Hash,
            virusScan: originalFile.virusScan
        });

        await newFile.save();
        res.status(201).json({ message: 'File saved to your account successfully.', url: `/w-upload/file/${newAlias}` });
    } catch (error) {
        res.status(500).json({ message: 'Import failed.' });
    }
});

router.get('/files/:alias/qrcode', async (req, res) => {
    try {
        const file = await File.findOne({ customAlias: req.params.alias });
        if (!file) return res.status(404).send('File not found');
        
        const url = `${req.protocol}://${req.get('host')}/w-upload/file/${file.customAlias}`;
        const qr = await qrcode.toDataURL(url);
        res.json({ qrCode: qr });
    } catch (e) {
        res.status(500).json({ message: 'QR Generation failed' });
    }
});

router.post('/files/:id/scan', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return res.status(404).json({ message: 'File not found' });

        if (file.virusScan.status === 'clean' || file.virusScan.status === 'infected') {
            return res.json({ status: file.virusScan.status, permalink: file.virusScan.permalink });
        }

        if (!file.sha256Hash) {
            const buffer = Buffer.from(file.base64.split(',')[1], 'base64');
            file.sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');
            await file.save();
        }

        const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${file.sha256Hash}`, {
            headers: { 'x-apikey': process.env.VT_API_KEY }
        });

        const stats = vtResponse.data.data.attributes.last_analysis_stats;
        const status = stats.malicious > 0 ? 'infected' : 'clean';
        const permalink = vtResponse.data.data.links.self; 

        file.virusScan = { status, lastChecked: new Date(), permalink };
        await file.save();

        res.json({ status, permalink });
    } catch (error) {
        if (error.response && error.response.status === 404) {
             return res.json({ status: 'unknown', message: 'File not found in VirusTotal database yet.' });
        }
        res.status(500).json({ message: 'Scan failed' });
    }
});

router.post('/report/:identifier', async (req, res) => {
    const { reason, category } = req.body;
    const file = await File.findOne({ customAlias: req.params.identifier });
    if (!file) return res.status(404).json({ message: 'File not found.' });
    file.reports.push({ reason: category ? `${category}: ${reason}` : reason });
    await file.save();
    res.status(200).json({ message: 'Report submitted.' });
});

router.post('/profile/passkey/register-options', auth.protectApi, async (req, res) => {
    try {
        const user = req.user;
        const options = await generateRegistrationOptions({
            rpName: passkeyConfig.rpName,
            rpID: passkeyConfig.rpID,
            userID: user._id.toString(),
            userName: user.username,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required',
            },
        });

        user.currentChallenge = options.challenge;
        await user.save();

        res.json(options);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 2. Verifikasi & Simpan
router.post('/profile/passkey/verify-registration', auth.protectApi, async (req, res) => {
    const user = req.user;
    const body = req.body;

    try {
        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: passkeyConfig.origin,
            expectedRPID: passkeyConfig.rpID,
        });

        if (verification.verified) {
            const { credentialPublicKey, credentialID, counter, transports } = verification.registrationInfo;
            
            user.passkeys.push({
                credentialID: Buffer.from(credentialID),
                credentialPublicKey: Buffer.from(credentialPublicKey),
                counter,
                transports: transports || [],
            });
            
            user.currentChallenge = undefined;
            await user.save();
        }

        res.json({ verified: verification.verified });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 3. Hapus Passkey
router.delete('/profile/passkey/:id', auth.protectApi, async (req, res) => {
    try {
        const credentialIdBase64 = req.params.id;
        
        await User.updateOne(
            { _id: req.user._id },
            { $pull: { passkeys: { credentialID: Buffer.from(credentialIdBase64, 'base64') } } }
        );

        res.json({ message: 'Passkey removed.' });
    } catch (e) {
        res.status(500).json({ error: 'Failed to remove passkey.' });
    }
});

module.exports = router;
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jimp = require('jimp');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const File = require('../models/file');
const User = require('../models/user');
const auth = require('../middleware/auth');

router.post('/upload', auth.protectApi, async (req, res) => {
    try {
        let { filename, contentType, base64, watermarkText } = req.body;
        let finalAlias = filename;
        let counter = 1;

        while (await File.findOne({ customAlias: finalAlias })) {
            const ext = path.extname(filename);
            const name = path.basename(filename, ext);
            finalAlias = `${name} (${counter})${ext}`;
            counter++;
        }

        if (contentType.startsWith('image/') && watermarkText) {
            const buffer = Buffer.from(base64.split(',')[1], 'base64');
            const image = await jimp.read(buffer);
            const font = await jimp.loadFont(jimp.FONT_SANS_32_WHITE);
            image.print(font, 10, image.bitmap.height - 40, watermarkText);
            base64 = await image.getBase64Async(jimp.MIME_PNG);
        }
        
        const base64Data = base64.split(';base64,').pop();
        const fileSize = (base64Data.length * (3/4)) - (base64Data.endsWith('==') ? 2 : (base64Data.endsWith('=') ? 1 : 0));

        const newFile = new File({
            originalName: filename, customAlias: finalAlias, contentType, size: fileSize, base64, owner: req.user.id
        });
        await newFile.save();
        res.status(201).json({ status: 'success', url: `${req.protocol}://${req.get('host')}/w-upload/file/${finalAlias}`, filename: finalAlias });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Server error during file upload.' });
    }
});

router.put('/files/:id/protect', auth.protectApi, async (req, res) => {
    try {
        const file = await File.findOne({ _id: req.params.id, owner: req.user.id });
        if (!file) return res.status(404).json({ message: 'File not found.' });

        const { password, expires, limit } = req.body;
        if (password) file.password = await bcrypt.hash(password, 10);
        else file.password = undefined;

        if (expires) file.expiresAt = new Date(Date.now() + expires * 60 * 60 * 1000);
        else file.expiresAt = undefined;

        if (limit) file.downloadLimit = parseInt(limit, 10);
        else file.downloadLimit = undefined;

        await file.save();
        res.status(200).json({ message: 'File protection updated.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error.' });
    }
});

router.post('/report/:identifier', async (req, res) => {
    try {
        const { reason } = req.body;
        const file = await File.findOne({ customAlias: req.params.identifier });
        if (!file) return res.status(404).json({ message: 'File not found.' });
        file.reports.push({ reason });
        await file.save();
        res.status(200).json({ message: 'File reported successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error.' });
    }
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
        res.status(200).json({ message: '2FA enabled successfully.' });
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

module.exports = router;
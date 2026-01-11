const express = require('express');
const router = express.Router();
const File = require('../models/file');
const User = require('../models/user');
const AiLog = require('../models/aiLog');
const { r2, GetObjectCommand } = require('../utils/r2');
const { translateText } = require('../utils/tr');
const { getDocsContent } = require('../utils/docsLoader'); 
const auth = require('../middleware/auth');

const streamToString = (stream) =>
    new Promise((resolve, reject) => {
        const chunks = [];
        stream.on("data", (chunk) => chunks.push(chunk));
        stream.on("error", reject);
        stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });

function maskPII(text) {
    return text
        .replace(/\b[\w\.-]+@[\w\.-]+\.\w{2,4}\b/g, '[EMAIL PROTECTED]')
        .replace(/\b(\+62|0)[0-9]{9,12}\b/g, '[PHONE PROTECTED]');
}

router.post('/chat', auth.protectApi, async (req, res) => {
    try {
        const { message, context } = req.body;
        const userId = req.user.id;
        
        const userLang = context.language ? context.language.split('-')[0] : 'en';
        
        const englishQuery = await translateText(message, 'en', 'auto');
        const cleanMsg = englishQuery.toLowerCase().trim();
        
        let responseText = "";
        let action = null;

        if (cleanMsg.includes('who am i') || cleanMsg.includes('my profile')) {
            const user = await User.findById(userId);
            responseText = `You are **${user.username}**.\n\n- Plan: **${user.plan.toUpperCase()}**\n- Status: ${user.isVerified ? 'Verified' : 'Unverified'}\n- Joined: ${new Date(user.createdAt).toLocaleDateString()}`;
        }
        else if (cleanMsg.includes('storage') || cleanMsg.includes('quota') || cleanMsg.includes('files')) {
            const count = await File.countDocuments({ owner: userId, deletedAt: null });
            const user = await User.findById(userId);
            const usedMB = (user.storageUsed / 1024 / 1024).toFixed(2);
            responseText = `**Storage Stats:**\n- Active Files: ${count}\n- Used: **${usedMB} MB**\n- Limit: **${(user.storageLimit/1024/1024/1024).toFixed(0)} GB**`;
        }
        else if (cleanMsg.startsWith('read file') || cleanMsg.startsWith('open file')) {
            const filename = cleanMsg.replace(/^(read|open) file/, '').trim();
            const file = await File.findOne({ 
                owner: userId, 
                originalName: { $regex: filename, $options: 'i' },
                deletedAt: null
            });

            if (!file) {
                responseText = `File "${filename}" not found.`;
            } else if (file.storageType === 'r2' && file.r2Key) {
                try {
                    const command = new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: file.r2Key });
                    const r2Res = await r2.send(command);
                    const content = await streamToString(r2Res.Body);
                    const snippet = content.length > 800 ? content.substring(0, 800) + "\n...(truncated)" : content;
                    responseText = `**${file.originalName}**:\n\`\`\`\n${snippet}\n\`\`\``;
                } catch (e) {
                    responseText = "Error reading file content from cloud.";
                }
            } else {
                responseText = "This file type cannot be read as text.";
            }
        }
        else if (cleanMsg.includes('error') || cleanMsg.includes('fix')) {
            if (context.hasError && context.errorMessage) {
                responseText = `**Error Detected:** "${context.errorMessage}"\n\nTry checking your input or refreshing the page.`;
            } else {
                responseText = "I don't see any active errors on your screen.";
            }
        }
        else if (cleanMsg.includes('go to') || cleanMsg.includes('navigate')) {
            const page = cleanMsg.includes('setting') ? '/profile' : '/dashboard';
            responseText = "Navigating...";
            action = { type: 'navigate', url: page };
        }
        else if (cleanMsg.includes('help') || cleanMsg.includes('features')) {
            try {
                const { getDocsContent } = require('../utils/docsLoader');
                const docs = getDocsContent();
                responseText = `**Knowledge Base:**\n\n${docs.substring(0, 500)}...\n\nVisit /docs for full details.`;
            } catch (e) {
                responseText = "Check the /docs page for full features.";
            }
        }
        else {
            responseText = "I can help you check storage, read files, explain errors, or navigate. Try asking 'How much storage do I have?'";
        }

        const finalResponse = await translateText(responseText, userLang, 'en');
        const maskedResponse = maskPII(finalResponse);

        const log = new AiLog({
            user: userId,
            query: message,
            response: maskedResponse,
            ip: req.ip
        });
        await log.save();

        res.json({ response: maskedResponse, action, logId: log._id });

    } catch (error) {
        console.error(error);
        res.status(500).json({ response: "System Error." });
    }
});

router.post('/feedback/:id', auth.protectApi, async (req, res) => {
    try {
        const { type } = req.body; 
        await AiLog.findByIdAndUpdate(req.params.id, { feedback: type });
        res.json({ message: 'Feedback received' });
    } catch (e) {
        res.status(500).json({ message: 'Error' });
    }
});

module.exports = router;
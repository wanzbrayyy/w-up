const User = require('../models/user');

exports.aiSecurityGuard = async (req, res, next) => {
    const aiKey = req.headers['x-ai-key'];
    
    if (req.originalUrl.includes('/api/ai/chat') && aiKey) {
        const user = await User.findOne({ 
            _id: req.user.id, 
            'apiKeys.key': aiKey,
            'apiKeys.label': 'AI_SERVICE' 
        });
        
        if (!user && !req.cookies.token) { 
            return res.status(403).json({ response: "Access denied. Invalid AI-Scoped API Key." });
        }
    }

    const { message } = req.body;
    if (message) {
        const forbiddenPatterns = [
            /ignore previous instructions/i,
            /system prompt/i,
            /delete database/i,
            /drop table/i,
            /rm -rf/i
        ];

        if (forbiddenPatterns.some(pattern => pattern.test(message))) {
            return res.status(400).json({ response: "Security Alert: Prompt Injection Detected." });
        }
    }

    next();
};
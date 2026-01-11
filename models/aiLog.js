const mongoose = require('mongoose');

const AiLogSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    query: { type: String, required: true },
    response: { type: String, required: true },
    feedback: { type: String, enum: ['like', 'dislike', 'none'], default: 'none' },
    ip: String,
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AiLog', AiLogSchema);
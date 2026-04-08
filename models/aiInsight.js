const mongoose = require('mongoose');

const AiInsightSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    kind: { type: String, default: 'upload_analysis' },
    title: { type: String, required: true },
    summary: { type: String, required: true },
    severity: { type: String, enum: ['info', 'success', 'warning'], default: 'info' },
    metadata: {
        fileId: { type: mongoose.Schema.Types.ObjectId, ref: 'File' },
        alias: String,
        filename: String,
        contentType: String,
        source: String,
        size: Number,
        suggestions: [String]
    },
    deliveredAt: { type: Date, default: null },
    readAt: { type: Date, default: null }
}, {
    timestamps: true
});

module.exports = mongoose.model('AiInsight', AiInsightSchema);

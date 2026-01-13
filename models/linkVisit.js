const mongoose = require('mongoose');

const LinkVisitSchema = new mongoose.Schema({
    file: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
    shareLinkId: { type: String, required: true },
    ip: { type: String },
    userAgent: { type: String },
    geo: {
        country: String,
        city: String,
    },
    type: { type: String, enum: ['view', 'download'], required: true },
    timestamp: { type: Date, default: Date.now }
});

LinkVisitSchema.index({ file: 1, shareLinkId: 1 });

module.exports = mongoose.model('LinkVisit', LinkVisitSchema);
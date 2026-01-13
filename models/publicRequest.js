const mongoose = require('mongoose');

const PublicRequestSchema = new mongoose.Schema({
    requestType: {
        type: String,
        enum: ['scraper', 'website', 'bot'],
        required: true
    },
    contactEmail: {
        type: String,
        required: true
    },
    details: {
        url: String,
        description: String,
        botType: String
    },
    status: {
        type: String,
        enum: ['Pending', 'In Progress', 'Completed', 'Rejected'],
        default: 'Pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('PublicRequest', PublicRequestSchema);
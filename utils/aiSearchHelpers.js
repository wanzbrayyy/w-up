const mongoose = require('mongoose');
const File = require('../models/file');
const User = require('../models/user');
const { extractContent } = require('./fileProcessor');

function formatFileResults(files) {
    if (!files || files.length === 0) return "No files found matching your criteria.";
    return files.map(f => `- **${f.originalName}** (Size: ${(f.size / 1024 / 1024).toFixed(2)} MB)`).join('\n');
}

function parseDateRange(query) {
    const now = new Date();
    const today = new Date(now.setHours(0, 0, 0, 0));
    const tomorrow = new Date(new Date(today).setDate(today.getDate() + 1));
    const yesterday = new Date(new Date(today).setDate(today.getDate() - 1));
    
    if (query.includes('today')) return { $gte: today, $lt: tomorrow };
    if (query.includes('yesterday')) return { $gte: yesterday, $lt: today };
    if (query.includes('last 7 days')) {
        const lastWeek = new Date(new Date(today).setDate(today.getDate() - 7));
        return { $gte: lastWeek, $lt: tomorrow };
    }
    return null;
}

async function searchFileContent(userId, teams, searchQuery) {
    const files = await File.find({
        owner: userId,
        contentType: { $in: [/pdf/, /text/, /javascript/, /json/, /markdown/, /msword/, /vnd.openxmlformats-officedocument.wordprocessingml.document/] },
        deletedAt: null
    });

    const matches = [];
    for (const file of files) {
        try {
            const content = await extractContent(file);
            if (content.toLowerCase().includes(searchQuery.toLowerCase())) {
                matches.push(file);
            }
        } catch (e) {
            // Ignore files that can't be read
        }
    }
    return matches;
}

async function findSimilarFilesByName(userId, fileName) {
    const baseName = fileName.replace(/\.[^/.]+$/, "").replace(/[\s\-_]/g, ' ').replace(/copy|final|v\d/gi, '').trim();
    if (baseName.length < 4) return [];
    
    const searchRegex = new RegExp(baseName.split(' ').join('|'), 'i');
    return File.find({ owner: userId, originalName: searchRegex, deletedAt: null });
}

module.exports = {
    formatFileResults,
    parseDateRange,
    searchFileContent,
    findSimilarFilesByName,
};
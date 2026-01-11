const mongoose = require('mongoose');
const User = require('../models/user');
const File = require('../models/file');
const Team = require('../models/team');

const readOnlyConn = mongoose.createConnection(process.env.MONGO_URI);

const AI_SCHEMA_MAP = {
    User: "username, email, role, plan, storageUsed, storageLimit, isVerified, createdAt",
    File: "originalName, size, contentType, downloads, virusScan, createdAt",
    Team: "name, members, storageQuota, usedStorage"
};

const privacyFilter = (data) => {
    if (!data) return null;
    const obj = data.toObject ? data.toObject() : data;
    const { password, twoFactorSecret, apiKeys, __v, sessions, ...safeData } = obj;
    return safeData;
};

const getUserProfile = async (userId) => {
    const user = await User.findById(userId).select('-password -twoFactorSecret -apiKeys');
    return privacyFilter(user);
};

const getStorageStats = async (userId) => {
    const user = await User.findById(userId);
    const count = await File.countDocuments({ owner: userId, deletedAt: null });
    return {
        files: count,
        used: (user.storageUsed / 1024 / 1024).toFixed(2) + ' MB',
        limit: (user.storageLimit / 1024 / 1024 / 1024).toFixed(2) + ' GB',
        plan: user.plan
    };
};

const searchUsers = async (query, requesterRole) => {
    if (requesterRole !== 'admin') return "Access Denied: Admin privileges required to search users.";
    
    const users = await User.find({ 
        $or: [{ username: { $regex: query, $options: 'i' } }, { email: { $regex: query, $options: 'i' } }] 
    }).limit(5).select('username email role plan isVerified');
    
    return users.length ? users.map(u => `${u.username} (${u.role}) - ${u.plan}`).join('\n') : "No users found.";
};

const getTeamData = async (userId) => {
    const user = await User.findById(userId);
    const teams = await Team.find({ _id: { $in: user.teams } }).populate('members', 'username email');
    
    if (!teams.length) return "You are not in any team.";
    
    return teams.map(t => {
        const members = t.members.map(m => m.username).join(', ');
        return `Team: ${t.name}\nMembers: ${members}\nStorage: ${(t.usedStorage/1024/1024).toFixed(2)} MB`;
    }).join('\n\n');
};

const getActivityLog = async (userId) => {
    const user = await User.findById(userId);
    if (!user.loginHistory || user.loginHistory.length === 0) return "No activity logs found.";
    
    return user.loginHistory.slice(0, 5).map(log => 
        `- ${new Date(log.date).toLocaleString()}: IP ${log.ip} (${log.os})`
    ).join('\n');
};

module.exports = {
    readOnlyConn,
    AI_SCHEMA_MAP,
    privacyFilter,
    getUserProfile,
    getStorageStats,
    searchUsers,
    getTeamData,
    getActivityLog
};
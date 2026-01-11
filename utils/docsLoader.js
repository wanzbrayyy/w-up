const fs = require('fs');
const path = require('path');

const getDocsContent = () => {
    try {
        const filePath = path.join(__dirname, '../views/docs.ejs');
        const content = fs.readFileSync(filePath, 'utf8');
        return content.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    } catch (e) {
        return "Documentation not available.";
    }
};

module.exports = { getDocsContent };
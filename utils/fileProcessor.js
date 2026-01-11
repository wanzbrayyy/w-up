const { r2, GetObjectCommand } = require('./r2');
const pdf = require('pdf-parse');
const mammoth = require('mammoth');
const Tesseract = require('tesseract.js');

const streamToBuffer = async (stream) => {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks);
};

const chunkText = (text, chunkSize = 1000) => {
    const chunks = [];
    for (let i = 0; i < text.length; i += chunkSize) {
        chunks.push(text.slice(i, i + chunkSize));
    }
    return chunks;
};

const extractContent = async (file) => {
    if (file.storageType !== 'r2' || !file.r2Key) {
        throw new Error('File not in cloud storage.');
    }

    const command = new GetObjectCommand({
        Bucket: process.env.R2_BUCKET_NAME,
        Key: file.r2Key
    });
    
    const r2Res = await r2.send(command);
    const buffer = await streamToBuffer(r2Res.Body);
    const mime = file.contentType;

    let text = '';

    if (mime === 'application/pdf') {
        const data = await pdf(buffer);
        text = data.text;
    } 
    else if (mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
        const result = await mammoth.extractRawText({ buffer });
        text = result.value;
    }
    else if (mime.startsWith('image/')) {
        const { data: { text: ocrText } } = await Tesseract.recognize(buffer, 'eng');
        text = `[OCR Result]: ${ocrText}`;
    }
    else if (mime.match(/(text|json|javascript|xml|html|css)/)) {
        text = buffer.toString('utf-8');
    }
    else {
        text = 'Unsupported file type for reading.';
    }

    return text.trim();
};

const summarizeText = (text) => {
    if (!text) return "No content to summarize.";
    const sentences = text.split(/[.!?]/).filter(s => s.trim().length > 0);
    const summary = sentences.slice(0, 5).join('. ') + (sentences.length > 5 ? '...' : '');
    return summary;
};

const searchInText = (text, query) => {
    const chunks = chunkText(text, 500);
    const results = chunks.filter(chunk => chunk.toLowerCase().includes(query.toLowerCase()));
    return results.slice(0, 3).join('\n---\n');
};

module.exports = { extractContent, chunkText, summarizeText, searchInText };
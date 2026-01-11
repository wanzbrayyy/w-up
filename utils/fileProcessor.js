const { r2, GetObjectCommand } = require('./r2');
const mammoth = require('mammoth');
const Tesseract = require('tesseract.js');
// Import pdf-parse dengan error handling jika module crash saat load
let pdf;
try {
    pdf = require('pdf-parse');
} catch (e) {
    console.warn("Warning: pdf-parse module could not be loaded.", e);
}

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
        if (pdf) {
            try {
                // Gunakan opsi render default
                const data = await pdf(buffer);
                text = data.text;
            } catch (e) {
                console.error("PDF Parsing Error:", e.message);
                text = "[Error reading PDF content. File might be encrypted or corrupted.]";
            }
        } else {
            text = "[PDF Parser not available on this server]";
        }
    } 
    else if (mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
        try {
            const result = await mammoth.extractRawText({ buffer });
            text = result.value;
        } catch (e) {
            text = "[Error reading DOCX content]";
        }
    }
    else if (mime.startsWith('image/')) {
        try {
            const { data: { text: ocrText } } = await Tesseract.recognize(buffer, 'eng');
            text = `[OCR Result]: ${ocrText}`;
        } catch (e) {
            text = "[Error processing Image OCR]";
        }
    }
    else if (mime.match(/(text|json|javascript|xml|html|css|markdown)/)) {
        text = buffer.toString('utf-8');
    }
    else {
        text = 'Unsupported file type for content reading. Only PDF, DOCX, Images, and Text files are supported.';
    }

    // Bersihkan teks dari karakter null atau whitespace berlebih
    return text.replace(/\0/g, '').trim();
};

const summarizeText = (text) => {
    if (!text || text.length < 50) return "Content too short to summarize.";
    
    // Simple logic: Ambil 3-5 kalimat pertama yang signifikan
    const sentences = text.split(/[.!?]/)
        .map(s => s.trim())
        .filter(s => s.length > 20); // Hanya ambil kalimat > 20 huruf
        
    const summary = sentences.slice(0, 5).join('. ') + (sentences.length > 5 ? '...' : '.');
    return summary;
};

const searchInText = (text, query) => {
    if (!text) return null;
    
    const lowerText = text.toLowerCase();
    const lowerQuery = query.toLowerCase();
    
    if (!lowerText.includes(lowerQuery)) return null;

    // Cari potongan teks sekitar keyword (Context window)
    const index = lowerText.indexOf(lowerQuery);
    const start = Math.max(0, index - 100);
    const end = Math.min(text.length, index + query.length + 100);
    
    const snippet = text.substring(start, end).replace(/\n/g, ' ');
    return `...${snippet}...`;
};

module.exports = { extractContent, chunkText, summarizeText, searchInText };
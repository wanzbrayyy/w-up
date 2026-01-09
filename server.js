const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const mongoURI = "mongodb+srv://maverickuniverse405:1m8MIgmKfK2QwBNe@cluster0.il8d4jx.mongodb.net/tod?retryWrites=true&w=majority&appName=Cluster0";

let cachedDb = null;
async function connectToDatabase() {
    if (cachedDb) return cachedDb;
    const client = await mongoose.connect(mongoURI);
    cachedDb = client;
    return cachedDb;
}

const FileSchema = new mongoose.Schema({
    originalName: String,
    extension: String,
    contentType: String,
    base64: String,
    size: Number,
    customAlias: { type: String, unique: true },
    createdAt: { type: Date, default: Date.now }
});

const FileModel = mongoose.models.File || mongoose.model('File', FileSchema);

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/docs', (req, res) => {
    res.render('docs');
});

function getBase64Size(base64String) {
    let padding = 0;
    if (base64String.endsWith('==')) padding = 2;
    else if (base64String.endsWith('=')) padding = 1;
    return (base64String.length * (3/4)) - padding;
}

app.post('/api/upload', async (req, res) => {
    await connectToDatabase();
    try {
        const { filename, contentType, base64, customAlias } = req.body;
        
        const finalAlias = customAlias || filename; 

        const exists = await FileModel.findOne({ customAlias: finalAlias });
        if (exists) {
            return res.status(400).json({ 
                status: 'error', 
                message: `File name '${finalAlias}' already exists. Please rename the file or use a custom URL.` 
            });
        }

        const base64Data = base64.split(';base64,').pop();
        const fileSize = getBase64Size(base64Data);
        const ext = path.extname(filename) || '';

        const newFile = new FileModel({
            originalName: filename,
            extension: ext,
            contentType,
            base64,
            size: fileSize,
            customAlias: finalAlias
        });

        await newFile.save();
        
        const fullUrl = `${req.protocol}://${req.get('host')}/w-upload/file/${finalAlias}`;
        
        res.json({ status: 'success', url: fullUrl });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.get('/w-upload/file/:identifier', async (req, res) => {
    await connectToDatabase();
    try {
        const identifier = req.params.identifier;
        const file = await FileModel.findOne({ customAlias: identifier }).select('-base64');
        
        if (!file) return res.status(404).render('404', { identifier });

        res.render('download', { 
            file: file, 
            downloadLink: `/w-upload/raw/${identifier}`,
            identifier: identifier
        });
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.get('/w-upload/raw/:identifier', async (req, res) => {
    await connectToDatabase();
    try {
        const identifier = req.params.identifier;
        const file = await FileModel.findOne({ customAlias: identifier });

        if (!file) return res.status(404).send('File Not Found');

        const base64Data = file.base64.split(';base64,').pop();
        const imgBuffer = Buffer.from(base64Data, 'base64');

        res.writeHead(200, {
            'Content-Type': file.contentType,
            'Content-Length': imgBuffer.length,
            'Content-Disposition': `attachment; filename="${file.originalName}"`
        });
        res.end(imgBuffer);
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
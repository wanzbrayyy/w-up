require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const hpp = require('hpp');
const csurf = require('csurf');
const SystemConfig = require('./models/systemConfig');
const { loadSystemConfig } = require('./middleware/system');

const app = express();

// Import Routes
const authRoutes = require('./routes/auth');
const viewRoutes = require('./routes/view');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');
const aiRoutes = require('./routes/ai'); 

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'", 
        "'unsafe-inline'", 
        "cdnjs.cloudflare.com", 
        "cdn.plyr.io", 
        "cdn.jsdelivr.net", 
        "pagead2.googlesyndication.com",
        "partner.googleadservices.com",
        "www.googletagservices.com",
        "tpc.googlesyndication.com"
      ],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", 
        "cdnjs.cloudflare.com", 
        "cdn.plyr.io", 
        "fonts.googleapis.com"
      ],
      fontSrc: ["'self'", "cdnjs.cloudflare.com", "fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:", "*"], 
      mediaSrc: ["'self'", "data:", "blob:"],
      frameSrc: [
        "'self'", 
        "docs.google.com", 
        "googleads.g.doubleclick.net", 
        "tpc.googlesyndication.com",
        "www.google.com"
      ],
      connectSrc: ["'self'", "pagead2.googlesyndication.com"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: process.env.APP_URL || 'https://wanzofc.site', 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'X-CSRF-Token']
}));

app.use(hpp());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// CSRF Configuration
const csrfProtection = csurf({ cookie: true });

// Middleware untuk CSRF dengan pengecualian untuk API
app.use((req, res, next) => {
  // Lewati CSRF jika ada header x-api-key ATAU jika request mengarah ke endpoint API/Auth
  // Ini penting agar fetch request untuk passkey/login tidak error 403
  if (req.headers['x-api-key'] || req.path.startsWith('/api/') || req.path.startsWith('/api/auth/')) {
    return next();
  }
  csrfProtection(req, res, next);
});

// Set locals csrfToken untuk View
app.use((req, res, next) => {
  if (req.csrfToken) {
    res.locals.csrfToken = req.csrfToken();
  }
  next();
});

app.use(loadSystemConfig);

app.get('/ads.txt', async (req, res) => {
    try {
        const config = await SystemConfig.getConfig();
        res.set('Content-Type', 'text/plain');
        res.send(config.adsTxtContent || '');
    } catch (e) {
        res.status(500).send('Error loading ads.txt');
    }
});

// ROUTE MOUNTING (Urutan Penting)
// 1. Mount Auth Routes ke /api/auth agar sesuai dengan fetch di frontend
app.use('/api/auth', authRoutes);

// 2. Mount API Routes lainnya
app.use('/api/ai', aiRoutes);
app.use('/api', apiRoutes);

// 3. Mount Admin & View Routes
app.use('/admin', adminRoutes);
app.use('/', viewRoutes);

// Error Handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ status: 'error', message: 'Invalid or missing CSRF Token' });
  }
  console.error(err);
  res.status(500).json({ status: 'error', message: 'Internal Server Error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;
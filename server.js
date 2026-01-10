require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');
const { loadSystemConfig } = require('./middleware/system');
const app = express();
const authRoutes = require('./routes/auth');
const viewRoutes = require('./routes/view');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin'); 
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));
app.use(loadSystemConfig);

app.use('/', authRoutes);
app.use('/admin', adminRoutes);
app.use('/', viewRoutes);
app.use('/api', apiRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;
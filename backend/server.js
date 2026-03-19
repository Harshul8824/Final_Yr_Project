require('dotenv').config({ path: require('path').resolve(__dirname, 'config.env') });
const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const path = require('path');
const mongoose = require('mongoose');


const app = express();
const port = parseInt(process.env.PORT, 10) || 5000;

// app.use(cors());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://your-vercel-app.vercel.app', // apna vercel URL daalo
    '*' // ya temporarily sab allow karo
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());


const whois = require('./routes/whois');
const vpndetect = require('./routes/vpndetect');
const batchProcess = require('./routes/batchProcess');
const analytics = require('./routes/analytics');
const advancedSearch = require('./routes/advancedSearch');
const auth = require('./routes/auth');
const history = require('./routes/history');

app.use('/api/whois', whois);
app.use('/api/vpndetect', vpndetect);
app.use('/api/batchprocess', batchProcess);
app.use('/api/analytics', analytics);
app.use('/api/advancedsearch', advancedSearch);
app.use('/api/auth', auth);
app.use('/api/history', history);



async function start() {
  //connect to local DB
  // const mongoUri = process.env.MONGO_URI;

  //connest atlas db
  const mongoUri = process.env.DATABASE.replace('<PASSWORD>', process.env.DB_PASSWORD);

  if (!mongoUri) {
    console.error('MONGO_URI is missing in backend/config.env');
    process.exit(1);
  }
  if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is missing in backend/config.env');
    process.exit(1);
  }

  try {
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 10000,
    });
    console.log('Connected to MongoDB');
  } catch (e) {
    console.error('MongoDB connection failed:', e.message);
    process.exit(1);
  }

  app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
    console.log(`MERN Stack VPN Detection System - Backend Ready!`);
  });
}

start();
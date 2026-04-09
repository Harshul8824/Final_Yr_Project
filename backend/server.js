require('dotenv').config({ path: require('path').resolve(__dirname, 'config.env') });
const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const path = require('path');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');


const app = express();
const port = parseInt(process.env.PORT, 10) || 5000;

//Global API limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many req for this IP, please try again after 15 minutes'
})

  app.use(globalLimiter);

//manually disable  "x-powered-by - express" so protect that application tech stack
app.disable('x-powered-by');

//security middleware
app.use(helmet());  //sanitize http headers

app.use(cors({
  origin: [
    'https://final-yr-project-three.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//NOSQL injection protection
app.use(mongoSanitize());

//xss clean
app.use(xss());

//prevent http parameter pollution
app.use(hpp());

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

  if (process.env.NODE_ENV !== 'test') {
    app.listen(port, () => {
      console.log(`Server is running on port: ${port}`);
      console.log(`MERN Stack VPN Detection System - Backend Ready!`);
    });
  }
}

start();

module.exports = app;
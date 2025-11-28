const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');
require('dotenv').config();
const path = require('path');


const app = express();
const port = process.env.PORT || 3000;

// app.use(cors());
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://final-year-project-os5j.vercel.app/"
  ],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());


const whois = require('./routes/whois');
const vpndetect = require('./routes/vpndetect');
const batchProcess = require('./routes/batchProcess');
const analytics = require('./routes/analytics');
const advancedSearch = require('./routes/advancedSearch');


app.use('/api/whois', whois);
app.use('/api/vpndetect', vpndetect);
app.use('/api/batchprocess', batchProcess);
app.use('/api/analytics', analytics);
app.use('/api/advancedsearch', advancedSearch);

app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
    console.log(`MERN Stack VPN Detection System - Backend Ready!`);
});
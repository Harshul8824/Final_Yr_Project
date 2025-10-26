# Backend Setup Instructions

## Prerequisites
- Node.js (v14 or higher)
- Python 3.7+
- npm or yarn

## Installation

1. Install dependencies:
```bash
npm install
```

2. Install Python dependencies:
```bash
pip install pandas numpy scikit-learn joblib
```

3. Create a `.env` file in the backend directory with the following variables:
```
PORT=5000
IP_QUALITY_SCORE_API_KEY=your_api_key_here
GET_IP_INTEL_CONTACT_EMAIL=your_email@example.com
IP2PROXY_DATABASE_PATH=../data/large.BIN
```

## Database Setup

1. Download the IP2Proxy database file and place it in the `../data/` directory
2. Ensure the ML models are trained and placed in `./MLServerCode/models/`

## Running the Server

```bash
npm start
```

The server will start on port 5000 (or the port specified in your .env file).

## API Endpoints

- `/api/whois/getrecord` - Get WHOIS information
- `/api/vpndetect/vpnports` - VPN port scanning
- `/api/vpndetect/checkcidr` - Check IP in CIDR
- `/api/vpndetect/qualityscore` - Get IP quality score
- `/api/vpndetect/intelscore` - Get ML intelligence score
- `/api/vpndetect/ipsearch` - Local IP search
- `/api/vpndetect/checkorg` - Check organization
- `/api/vpndetect/checkip` - Check IP in VPN list
- `/api/batchprocess/processfile` - Batch process IPs
- `/api/analytics/getallanalytics` - Get analytics data
- `/api/advancedsearch/quickscan` - Quick network scan
- `/api/advancedsearch/fullscan` - Full network scan

## Notes

- Make sure all Python scripts are executable
- Ensure proper file permissions for the ML server code
- The cron jobs will run automatically for data generation and model training


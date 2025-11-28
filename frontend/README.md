<<<<<<< HEAD
# VPN Detection System - Frontend (React.js)

A modern React.js frontend for the VPN Detection System with comprehensive security analysis tools.

## 🚀 Features

- **Dashboard**: Overview of system analytics and quick access to tools
- **WHOIS Lookup**: Detailed domain and IP information retrieval
- **VPN Detection**: Multi-method VPN and proxy detection
- **Batch Processing**: Upload files for bulk IP analysis (Coming Soon)
- **Network Scanning**: Advanced port scanning (Coming Soon)
- **Analytics**: Detailed reporting and logs (Coming Soon)

## 🛠️ Tech Stack

- **React 18** with JavaScript
- **Tailwind CSS** for styling
- **Axios** for API communication
- **Lucide React** for icons
- **React Hot Toast** for notifications

## 📦 Installation

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start development server:**
   ```bash
   npm start
   ```

3. **Build for production:**
   ```bash
   npm run build
   ```

## 🔧 Configuration

Create a `.env` file in the root directory:

```env
# API Configuration
REACT_APP_API_URL=http://localhost:5000/api

# App Configuration
REACT_APP_NAME=VPN Detection System
REACT_APP_VERSION=1.0.0

# Development
REACT_APP_DEBUG=true
```

## 🌐 API Integration

The frontend integrates with the backend API endpoints:

- `/api/whois/getrecord` - WHOIS lookup
- `/api/vpndetect/*` - VPN detection methods
- `/api/batchprocess/processfile` - Batch processing
- `/api/analytics/getallanalytics` - Analytics data
- `/api/advancedsearch/*` - Network scanning

## 📱 Responsive Design

- Mobile-first approach
- Responsive grid layouts
- Touch-friendly interface
- Optimized for all screen sizes

## 🎨 UI Components

- **Header**: Navigation with mobile menu
- **Dashboard**: Analytics overview and quick actions
- **ResultCard**: Reusable data display component
- **Forms**: Consistent input styling
- **Loading States**: Spinner and skeleton loading
- **Error Handling**: User-friendly error messages

## 🔒 Security Features

- Input validation and sanitization
- XSS protection
- Secure API communication
- Error boundary handling

## 🚀 Getting Started

1. **Ensure backend is running** on `http://localhost:5000`
2. **Start the frontend:**
   ```bash
   npm start
   ```
3. **Open browser** to `http://localhost:3000`

## 📁 Project Structure

```
src/
├── components/          # React components
│   ├── Header.js       # Navigation header
│   ├── Dashboard.js    # Main dashboard
│   ├── WhoisLookup.js  # WHOIS lookup form
│   ├── VpnDetection.js # VPN detection interface
│   └── ResultCard.js   # Data display component
├── services/           # API services
│   └── api.js         # API client and endpoints
├── App.js             # Main app component
├── index.js           # App entry point
└── index.css          # Global styles with Tailwind
```

## 🎯 Usage Examples

### WHOIS Lookup
```javascript
import { whoisService } from './services/api';

const result = await whoisService.getRecord('google.com');
console.log(result);
=======
# VPN Detection System - Complete Project

A comprehensive MERN stack application for VPN and proxy detection with machine learning capabilities.

## 🏗️ Project Structure

```
Final_Yr_Project/
├── backend/                 # Node.js Express API
│   ├── routes/             # API endpoints
│   ├── utilities/          # Helper functions
│   ├── MLServerCode/       # Python ML scripts
│   ├── server.js           # Main server file
│   └── package.json        # Backend dependencies
├── frontend/               # React.js UI (JavaScript)
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── services/       # API integration
│   │   └── App.js         # Main app
│   └── package.json       # Frontend dependencies
└── README.md              # This file
```

## 🚀 Quick Start

### Backend Setup
```bash
cd backend
npm install
npm start
```

### Frontend Setup (React.js)
```bash
cd frontend
npm install
npm start
```

### Access Points
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **API Documentation**: http://localhost:5000/api

## 🔧 Backend Features

### API Endpoints
- **WHOIS Lookup**: `/api/whois/getrecord`
- **VPN Detection**: `/api/vpndetect/*`
- **Batch Processing**: `/api/batchprocess/processfile`
- **Analytics**: `/api/analytics/getallanalytics`
- **Network Scanning**: `/api/advancedsearch/*`

### Security Features
- Input validation and sanitization
- XSS protection
- Timeout handling
- Error boundary management
- CORS configuration

### ML Integration
- Python scripts for ML model training
- Real-time prediction APIs
- Batch processing capabilities
- Analytics and logging

## 🎨 Frontend Features

### Components
- **Dashboard**: System overview and analytics
- **WHOIS Lookup**: Domain/IP information retrieval
- **VPN Detection**: Multi-method detection interface
- **Batch Processing**: File upload for bulk analysis
- **Network Scanning**: Port scanning interface
- **Analytics**: Detailed reporting dashboard

### UI/UX Features
- Responsive design (mobile-first)
- Modern Tailwind CSS styling
- Loading states and error handling
- Toast notifications
- Interactive forms and data display

## 🔒 Security Implementation

### Backend Security
- Input sanitization for suspicious patterns
- Host format validation
- DNS timeout handling
- API rate limiting (configurable)
- Error logging and monitoring

### Frontend Security
- XSS protection in forms
- Input validation
- Secure API communication
- Error boundary handling
- CSRF protection

## 📊 ML Pipeline

### Data Processing
- CSV data ingestion
- Feature extraction
- Model training with scikit-learn
- Real-time prediction
- Batch processing

### Models
- OneClassSVM for anomaly detection
- OneHotEncoder for categorical data
- Model persistence with joblib

## 🧪 Testing

### Backend Testing
```bash
cd backend
npm test
```

### Frontend Testing
```bash
cd frontend
npm test
```

### Manual Testing
- Postman collection included
- Test scripts for API endpoints
- Comprehensive error handling tests

## 📈 Performance

### Backend Optimization
- Async/await for non-blocking operations
- Promise-based timeout handling
- Memory management for large datasets
- Efficient data processing

### Frontend Optimization
- Code splitting
- Lazy loading
- Memoization
- Optimized bundle size

## 🔧 Configuration

### Environment Variables
```env
# Backend
PORT=5000
IP_QUALITY_SCORE_API_KEY=your_key
GET_IP_INTEL_CONTACT_EMAIL=your_email

# Frontend
REACT_APP_API_URL=http://localhost:5000/api
```

### Dependencies
- **Backend**: Express, Axios, CORS, Node-schedule
- **Frontend**: React.js, JavaScript, Tailwind CSS, Axios
- **ML**: Python, pandas, scikit-learn, joblib

## 🚀 Deployment

### Backend Deployment
1. Install dependencies: `npm install`
2. Set environment variables
3. Start server: `npm start`

### Frontend Deployment
1. Install dependencies: `npm install`
2. Build: `npm run build`
3. Serve static files

### Production Considerations
- Environment variable configuration
- Database setup for ML models
- File storage for batch processing
- Monitoring and logging

## 📝 API Documentation

### WHOIS Endpoint
```javascript
POST /api/whois/getrecord
{
  "host": "google.com"
}
>>>>>>> b506c781d52fac87a2cfc706cd97138783b5e18c
```

### VPN Detection
```javascript
<<<<<<< HEAD
import { vpnDetectionService } from './services/api';

const result = await vpnDetectionService.qualityScore('8.8.8.8');
console.log(result);
```

## 🔧 Development

- **Hot reload** enabled
- **JavaScript** ES6+ features
- **Tailwind CSS** for styling
- **Axios** for HTTP requests

## 📊 Performance

- **Code splitting** for optimal loading
- **Lazy loading** for components
- **Memoization** for expensive operations
- **Optimized bundle** size
=======
POST /api/vpndetect/qualityscore
{
  "host": "8.8.8.8"
}
```

### Batch Processing
```javascript
POST /api/batchprocess/processfile
FormData with 'ipFile'
```
>>>>>>> b506c781d52fac87a2cfc706cd97138783b5e18c

## 🐛 Troubleshooting

### Common Issues
<<<<<<< HEAD

1. **API Connection Failed**
   - Ensure backend is running on port 5000
   - Check CORS configuration
   - Verify API URL in environment variables

2. **Styling Issues**
   - Ensure Tailwind CSS is properly configured
   - Check PostCSS configuration
   - Verify CSS imports

3. **Build Errors**
   - Clear node_modules and reinstall
   - Check JavaScript syntax
   - Verify all dependencies are installed

## 📝 License

This project is part of the VPN Detection System.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For support and questions, please refer to the main project documentation.
=======
1. **CORS Errors**: Check backend CORS configuration
2. **API Timeouts**: Verify timeout settings
3. **ML Model Errors**: Ensure Python dependencies
4. **Build Errors**: Clear node_modules and reinstall

### Debug Mode
- Backend: Set `DEBUG=true` in environment
- Frontend: Use React DevTools
- API: Check browser network tab

## 📊 Analytics

### System Metrics
- Total data points processed
- Training vs test data split
- ML model performance
- API response times
- Error rates

### Logging
- ML model training logs
- Data generation logs
- API request/response logs
- Error tracking

## 🔮 Future Enhancements

### Planned Features
- Real-time monitoring dashboard
- Advanced ML models
- Database integration
- User authentication
- API rate limiting
- Comprehensive testing suite

### Scalability
- Microservices architecture
- Load balancing
- Database clustering
- Caching layer
- CDN integration

## 📞 Support

For technical support and questions:
1. Check the troubleshooting section
2. Review API documentation
3. Check error logs
4. Verify configuration

## 📄 License

This project is developed for educational purposes as part of a final year project.

---

**Status**: ✅ Backend Complete | ✅ Frontend Complete (React.js) | 🚧 Additional Features Pending
>>>>>>> b506c781d52fac87a2cfc706cd97138783b5e18c

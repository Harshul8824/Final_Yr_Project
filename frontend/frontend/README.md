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
```

### VPN Detection
```javascript
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

## 🐛 Troubleshooting

### Common Issues

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
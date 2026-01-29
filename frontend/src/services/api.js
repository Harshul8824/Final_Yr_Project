import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  // Add retry configuration
  retry: 3,
  retryDelay: 1000,
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`Making ${config.method?.toUpperCase()} request to ${config.url}`);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    // Log successful responses for debugging
    console.log(`API Success: ${response.config.method?.toUpperCase()} ${response.config.url}`, response.data);
    return response;
  },
  (error) => {
    console.error('API Error:', {
      url: error.config?.url,
      method: error.config?.method,
      status: error.response?.status,
      data: error.response?.data,
      message: error.message
    });

    // Handle network errors specifically
    if (!error.response) {
      // Network error - backend not running or connection failed
      const networkError = new Error('Network Error: Unable to connect to the server. Please ensure the backend is running on port 5000.');
      networkError.isNetworkError = true;
      return Promise.reject(networkError);
    }

    return Promise.reject(error);
  }
);

// API Services
export const whoisService = {
  getRecord: async (host) => {
    const response = await api.post('/whois/getrecord', { host });
    return response.data;
  },
};

export const vpnDetectionService = {
  vpnPorts: async (host) => {
    const response = await api.post('/vpndetect/vpnports', { host });
    return response.data;
  },

  checkCidr: async (host) => {
    const response = await api.post('/vpndetect/checkcidr', { host });
    return response.data;
  },

  qualityScore: async (host) => {
    const response = await api.post('/vpndetect/qualityscore', { host });
    return response.data;
  },

  // ML intel score removed - using MERN stack only

  ipSearch: async (host) => {
    const response = await api.post('/vpndetect/ipsearch', { host });
    return response.data;
  },

  checkOrg: async (host) => {
    const response = await api.post('/vpndetect/checkorg', { host });
    return response.data;
  },

  checkIp: async (host) => {
    const response = await api.post('/vpndetect/checkip', { host });
    return response.data;
  },

  checkOnlineData: async (host) => {
    const response = await api.post('/vpndetect/checkonlinedata', { host });
    return response.data;
  },

  getRealIp: async () => {
    const response = await api.post('/vpndetect/getrealip', {});
    return response.data;
  },
};

export const batchProcessService = {
  processFile: async (file) => {
    const formData = new FormData();
    formData.append('ipFile', file);

    const response = await api.post('/batchprocess/processfile', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
};

export const analyticsService = {
  getAllAnalytics: async () => {
    const response = await api.get('/analytics/getallanalytics');
    return response.data;
  },
};

export const advancedSearchService = {
  quickScan: async (host) => {
    const response = await api.post('/advancedsearch/quickscan', { host });
    return response.data;
  },

  fullScan: async (host) => {
    const response = await api.post('/advancedsearch/fullscan', { host });
    return response.data;
  },
};

export default api;

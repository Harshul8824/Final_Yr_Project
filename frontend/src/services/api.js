import axios from 'axios';

// const API_BASE_URL = 'http://localhost:5000/api';
const API_BASE_URL = 'https://final-yr-project-1-v8hj.onrender.com/api';

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
    // Attach auth token if present
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
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
      const networkError = new Error('Network Error: Unable to connect to the server.');
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

export const authService = {
  register: async ({ name, email, password }) => {
    const response = await api.post('/auth/register', { name, email, password });
    return response.data;
  },
  login: async ({ email, password }) => {
    const response = await api.post('/auth/login', { email, password });
    return response.data;
  },
  me: async () => {
    const response = await api.get('/auth/me');
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
  getDashboard: async () => {
    const response = await api.get('/analytics/dashboard');
    return response.data;
  }
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

export const historyService = {
  save: async (data) => {
    const response = await api.post('/history/save', data);
    return response.data;
  },
  getMyHistory: async () => {
    const response = await api.get('/history/myhistory');
    return response.data;
  },
  clearHistory: async () => {
    const response = await api.delete('/history/clear');
    return response.data;
  }
};

export default api;

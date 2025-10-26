import React, { useState } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { vpnDetectionService } from '../services/api';
import ResultCard from './ResultCard';

const VpnDetection = () => {
  const [host, setHost] = useState('');
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState({});
  const [error, setError] = useState(null);

  const detectionMethods = [
    {
      id: 'vpnports',
      name: 'VPN Port Scan',
      description: 'Scan for common VPN ports (1723, 1701, 500, 4500, 1194, 443)',
      icon: Search,
    },
    {
      id: 'qualityscore',
      name: 'Quality Score',
      description: 'Get IP quality score and fraud detection',
      icon: Shield,
    },
    {
      id: 'intelscore',
      name: 'Intel Score',
      description: 'ML-based intelligence score for IP analysis',
      icon: AlertTriangle,
    },
    {
      id: 'ipsearch',
      name: 'Local IP Search',
      description: 'Search IP in local proxy/VPN database',
      icon: Search,
    },
    {
      id: 'checkip',
      name: 'VPN List Check',
      description: 'Check if IP is in known VPN list',
      icon: Shield,
    },
    {
      id: 'checkonlinedata',
      name: 'Online Data Check',
      description: 'Check IP against online threat database',
      icon: AlertTriangle,
    },
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!host.trim()) {
      setError('Please enter a hostname or IP address');
      return;
    }

    setError(null);
    setResults({});

    // Run all detection methods
    for (const method of detectionMethods) {
      setLoading(prev => ({ ...prev, [method.id]: true }));
      
      try {
        let response;
        
        switch (method.id) {
          case 'vpnports':
            response = await vpnDetectionService.vpnPorts(host.trim());
            break;
          case 'qualityscore':
            response = await vpnDetectionService.qualityScore(host.trim());
            break;
          case 'intelscore':
            response = await vpnDetectionService.intelScore(host.trim());
            break;
          case 'ipsearch':
            response = await vpnDetectionService.ipSearch(host.trim());
            break;
          case 'checkip':
            response = await vpnDetectionService.checkIp(host.trim());
            break;
          case 'checkonlinedata':
            response = await vpnDetectionService.checkOnlineData(host.trim());
            break;
          default:
            continue;
        }
        
        setResults(prev => ({ ...prev, [method.id]: response }));
      } catch (err) {
        setResults(prev => ({ 
          ...prev, 
          [method.id]: { 
            error: err.response?.data?.msg || err.message || 'An error occurred' 
          } 
        }));
      } finally {
        setLoading(prev => ({ ...prev, [method.id]: false }));
      }
    }
  };

  const handleClear = () => {
    setHost('');
    setResults({});
    setError(null);
    setLoading({});
  };

  const getStatusIcon = (result) => {
    if (result.error) {
      return <XCircle className="h-5 w-5 text-red-500" />;
    }
    
    if (result.result === 1 || result.status === 'Host is Up') {
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    }
    
    if (result.result === 0 || result.status === 'Host is down') {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }
    
    return <Shield className="h-5 w-5 text-gray-500" />;
  };

  const getStatusText = (result) => {
    if (result.error) {
      return 'Error';
    }
    
    if (result.result === 1 || result.status === 'Host is Up') {
      return 'Suspicious';
    }
    
    if (result.result === 0 || result.status === 'Host is down') {
      return 'Clean';
    }
    
    return 'Unknown';
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-gray-900 mb-2">VPN Detection</h2>
        <p className="text-gray-600">
          Comprehensive VPN and proxy detection using multiple methods including port scanning, 
          ML analysis, and threat intelligence databases.
        </p>
      </div>

      {/* Search Form */}
      <div className="card mb-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="host" className="block text-sm font-medium text-gray-700 mb-2">
              Hostname or IP Address
            </label>
            <div className="relative">
              <input
                type="text"
                id="host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="e.g., 8.8.8.8 or suspicious-domain.com"
                className="input-field pl-10"
                disabled={Object.values(loading).some(l => l)}
              />
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Shield className="h-5 w-5 text-gray-400" />
              </div>
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              type="submit"
              disabled={Object.values(loading).some(l => l) || !host.trim()}
              className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {Object.values(loading).some(l => l) ? 'Analyzing...' : 'Detect VPN/Proxy'}
            </button>
            <button
              type="button"
              onClick={handleClear}
              className="btn-secondary"
              disabled={Object.values(loading).some(l => l)}
            >
              Clear
            </button>
          </div>
        </form>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <XCircle className="h-5 w-5 text-red-400" />
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <div className="mt-2 text-sm text-red-700">
                <p>{error}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Detection Methods */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {detectionMethods.map((method) => {
          const Icon = method.icon;
          const result = results[method.id];
          const isLoading = loading[method.id];
          
          return (
            <div key={method.id} className="card">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center">
                  <Icon className="h-6 w-6 text-primary-600 mr-3" />
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">{method.name}</h3>
                    <p className="text-sm text-gray-600">{method.description}</p>
                  </div>
                </div>
                {result && !isLoading && (
                  <div className="flex items-center">
                    {getStatusIcon(result)}
                    <span className="ml-2 text-sm font-medium">
                      {getStatusText(result)}
                    </span>
                  </div>
                )}
              </div>

              {isLoading && (
                <div className="flex items-center justify-center py-4">
                  <div className="loading-spinner"></div>
                  <span className="ml-2 text-gray-600">Analyzing...</span>
                </div>
              )}

              {result && !isLoading && (
                <ResultCard
                  title=""
                  data={result}
                  loading={false}
                  error={result.error || null}
                />
              )}
            </div>
          );
        })}
      </div>

      {/* Help Text */}
      <div className="mt-8 bg-blue-50 border border-blue-200 rounded-md p-4">
        <h3 className="text-sm font-medium text-blue-800 mb-2">Detection Methods:</h3>
        <ul className="text-sm text-blue-700 space-y-1">
          <li>• <strong>VPN Port Scan:</strong> Checks for common VPN service ports</li>
          <li>• <strong>Quality Score:</strong> External API-based fraud detection</li>
          <li>• <strong>Intel Score:</strong> Machine learning-based analysis</li>
          <li>• <strong>Local Search:</strong> Checks against local proxy database</li>
          <li>• <strong>VPN List:</strong> Compares against known VPN IP ranges</li>
          <li>• <strong>Online Data:</strong> Real-time threat intelligence lookup</li>
        </ul>
      </div>
    </div>
  );
};

export default VpnDetection;

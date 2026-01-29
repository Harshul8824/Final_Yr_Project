import React, { useState } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { vpnDetectionService } from '../services/api';
import ResultCard from './ResultCard';
import DebugInfo from './DebugInfo';

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
    // ML intel score removed - using MERN stack only
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

    // Run all detection methods with better error handling
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
          // ML intel score removed - using MERN stack only
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

        // Validate response before setting
        if (response && typeof response === 'object') {
          setResults(prev => ({ ...prev, [method.id]: response }));
        } else {
          setResults(prev => ({
            ...prev,
            [method.id]: {
              error: 'Invalid response received from server',
              result: null
            }
          }));
        }
      } catch (err) {
        console.error(`Error in ${method.name}:`, err);
        let errorMessage;
        if (err.isNetworkError) {
          errorMessage = 'Network Error: Unable to connect to the server. Please ensure the backend is running on port 5000.';
        } else {
          errorMessage = err.response?.data?.msg || err.message || 'An error occurred';
        }
        setResults(prev => ({
          ...prev,
          [method.id]: {
            error: errorMessage,
            result: null
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

    // Check for VPN/Proxy detection results
    if (result.result === 1 || result.result === true) {
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    }

    if (result.result === 0 || result.result === false) {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }

    // Check for port scan results
    if (result.status === 'Host is Up') {
      if (result.ports && result.ports.length > 0) {
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      }
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }

    if (result.status === 'Host is down' || result.status === 'Timeout' || result.status === 'Error') {
      return <XCircle className="h-5 w-5 text-red-500" />;
    }

    // Check for quality score results
    if (result.fraud_score !== undefined) {
      if (result.fraud_score > 0.5) {
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      } else {
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      }
    }

    return <Shield className="h-5 w-5 text-gray-500" />;
  };

  const getStatusText = (result) => {
    if (result.error) {
      return 'Error';
    }

    // Check for VPN/Proxy detection results
    if (result.result === 1 || result.result === true) {
      return 'VPN/Proxy Detected';
    }

    if (result.result === 0 || result.result === false) {
      return 'Clean';
    }

    // Check for port scan results
    if (result.status === 'Host is Up') {
      if (result.ports && result.ports.length > 0) {
        return `${result.openPortsCount || result.ports.length} Open Port(s)`;
      }
      return 'Host Up (No Open Ports)';
    }

    if (result.status === 'Host is down') {
      return 'Host Down';
    }

    if (result.status === 'Timeout') {
      return 'Scan Timeout';
    }

    if (result.status === 'Error') {
      return 'Scan Error';
    }

    // Check for quality score results
    if (result.fraud_score !== undefined) {
      if (result.fraud_score > 0.5) {
        return 'High Risk';
      } else {
        return 'Low Risk';
      }
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
                <>
                  {method.id === 'vpnports' ? (
                    <div className="space-y-3">
                      <div className="bg-gray-50 rounded-md p-3">
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm font-medium text-gray-700">Status:</span>
                          <span className={`text-sm font-semibold ${result.status === 'Host is Up' ? 'text-green-600' :
                            result.status === 'Host is down' ? 'text-red-600' :
                              'text-yellow-600'
                            }`}>
                            {result.status}
                          </span>
                        </div>
                        {result.scannedHost && (
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-sm font-medium text-gray-700">Scanned Host:</span>
                            <span className="text-sm text-gray-900">{result.scannedHost}</span>
                          </div>
                        )}
                        {result.hostname && result.hostname !== result.scannedHost && (
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-sm font-medium text-gray-700">Hostname:</span>
                            <span className="text-sm text-gray-900">{result.hostname}</span>
                          </div>
                        )}
                        {result.openPortsCount !== undefined && (
                          <div className="flex justify-between items-center">
                            <span className="text-sm font-medium text-gray-700">Open Ports:</span>
                            <span className="text-sm font-semibold text-gray-900">
                              {result.openPortsCount}
                            </span>
                          </div>
                        )}
                      </div>

                      {result.ports && result.ports.length > 0 && (
                        <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3">
                          <h4 className="text-sm font-semibold text-yellow-800 mb-2">Open Ports Detected:</h4>
                          <div className="space-y-2">
                            {result.ports.map((port, idx) => {
                              // Safely extract port number (handle object structures)
                              const getPortNumber = (portObj) => {
                                if (typeof portObj === 'number' || typeof portObj === 'string') {
                                  return String(portObj);
                                }
                                if (portObj?.item?.portid) return String(portObj.item.portid);
                                if (portObj?.item?.port) return String(portObj.item.port);
                                if (portObj?.portid) return String(portObj.portid);
                                if (portObj?.port) return String(portObj.port);
                                return 'Unknown';
                              };

                              // Safely extract protocol
                              const getProtocol = (portObj) => {
                                if (typeof portObj === 'string') return portObj;
                                return portObj?.protocol || portObj?.item?.protocol || 'tcp';
                              };

                              // Safely extract service/state
                              const getService = (portObj) => {
                                if (typeof portObj === 'string') return portObj;

                                const serviceName = portObj?.service ||
                                  portObj?.item?.service?.name ||
                                  portObj?.state ||
                                  portObj?.item?.state ||
                                  'open';

                                // Always return string
                                return typeof serviceName === 'object'
                                  ? JSON.stringify(serviceName)
                                  : String(serviceName);
                              };

                              const portNum = getPortNumber(port.port || port);
                              const protocol = getProtocol(port.protocol || port);
                              const service = getService(port);

                              return (
                                <div key={idx} className="flex justify-between items-center text-sm">
                                  <span className="font-medium text-yellow-900">
                                    Port {portNum} ({protocol})
                                  </span>
                                  <span className="text-yellow-700">
                                    {service}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {result.error && (
                        <div className="bg-red-50 border border-red-200 rounded-md p-3">
                          <p className="text-sm text-red-700">{result.error}</p>
                        </div>
                      )}

                      {result.msg && !result.error && (
                        <div className="bg-blue-50 border border-blue-200 rounded-md p-3">
                          <p className="text-sm text-blue-700">{result.msg}</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <>
                      <ResultCard
                        title=""
                        data={result}
                        loading={false}
                        error={result.error || null}
                      />
                      <DebugInfo result={result} methodName={method.name} />
                    </>
                  )}
                </>
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

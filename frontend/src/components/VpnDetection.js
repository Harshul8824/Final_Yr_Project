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

    // Quality Score: result can be object { proxy, vpn, torExit, fraud_score } or null (disabled)
    if (result.result && typeof result.result === 'object' && !Array.isArray(result.result)) {
      const r = result.result;
      if (r.torExit) return <AlertTriangle className="h-5 w-5 text-red-500" />;
      if (r.proxy || r.vpn) return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      if (r.fraud_score != null && r.fraud_score > 75) return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }
    if (result.result === null && result.note) {
      return <Shield className="h-5 w-5 text-gray-500" />;
    }

    // VPN/Proxy detection: result 0 or 1
    if (result.result === 1 || result.result === true) {
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    }
    if (result.result === 0 || result.result === false) {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }

    // Port scan results
    if (result.status === 'Host is Up') {
      if (result.ports && result.ports.length > 0) {
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      }
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }
    if (result.status === 'Host is down' || result.status === 'Timeout' || result.status === 'Error') {
      return <XCircle className="h-5 w-5 text-red-500" />;
    }

    if (result.fraud_score !== undefined) {
      if (result.fraud_score > 0.5) return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }

    return <Shield className="h-5 w-5 text-gray-500" />;
  };

  const getStatusText = (result) => {
    if (result.error) return 'Error';

    // Quality Score object or disabled
    if (result.result && typeof result.result === 'object' && !Array.isArray(result.result)) {
      const r = result.result;
      if (r.torExit) return 'Tor Exit (High Risk)';
      if (r.proxy || r.vpn) return 'VPN/Proxy Detected';
      if (r.fraud_score != null && r.fraud_score > 75) return 'High Risk';
      return 'Low Risk';
    }
    if (result.result === null && result.note) return 'Disabled';

    if (result.result === 1 || result.result === true) return 'VPN/Proxy Detected';
    if (result.result === 0 || result.result === false) return 'Clean';

    if (result.status === 'Host is Up') {
      if (result.ports && result.ports.length > 0) return `${result.openPortsCount || result.ports.length} Open Port(s)`;
      return 'Host Up (No Open Ports)';
    }
    if (result.status === 'Host is down') return 'Host Down';
    if (result.status === 'Timeout') return 'Scan Timeout';
    if (result.status === 'Error') return 'Scan Error';

    if (result.fraud_score !== undefined) {
      return result.fraud_score > 0.5 ? 'High Risk' : 'Low Risk';
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
                      {(() => {
                        // Safe string for React: never render objects
                        const safeStr = (v) => {
                          if (v == null) return '';
                          if (typeof v === 'string' || typeof v === 'number') return String(v);
                          if (Array.isArray(v)) {
                            const first = v[0];
                            if (first && typeof first === 'object' && first.item?.name) return String(first.item.name);
                            return v.map(x => safeStr(x)).join(', ');
                          }
                          if (typeof v === 'object') {
                            if (v.item?.name) return String(v.item.name);
                            if (v.item?.portid != null) return String(v.item.portid);
                            if (v.portid != null) return String(v.portid);
                            if (v.port != null && (typeof v.port === 'string' || typeof v.port === 'number')) return String(v.port);
                            return JSON.stringify(v);
                          }
                          return String(v);
                        };

                        // Normalize ports from API: { port, protocol, state, service } (all strings)
                        const portsList = (result.ports && Array.isArray(result.ports))
                          ? result.ports.map((p) => {
                              const portNum = typeof p.port === 'string' || typeof p.port === 'number' ? String(p.port) : safeStr(p?.port ?? p?.item ?? p);
                              const protocol = typeof p.protocol === 'string' ? p.protocol : safeStr(p?.protocol ?? 'tcp');
                              const state = typeof p.state === 'string' ? p.state : safeStr(p?.state ?? 'unknown');
                              const service = p?.service != null ? safeStr(p.service) : (state === 'open' ? 'open' : state);
                              return { port: portNum, protocol, state, service };
                            }).filter(({ port }) => port && port !== 'Unknown' && !String(port).startsWith('{'))
                          : [];

                        const openCount = portsList.filter((p) => p.state === 'open').length;
                        const filteredCount = portsList.filter((p) => p.state === 'filtered').length;
                        const displayHostname = safeStr(result.hostname) || safeStr(result.scannedHost);

                        return (
                          <>
                            {/* Status & summary */}
                            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
                              <div className="flex justify-between items-center mb-3">
                                <span className="text-sm font-medium text-gray-700">Status</span>
                                <span className={`text-sm font-semibold px-2 py-1 rounded ${safeStr(result.status) === 'Host is Up' ? 'text-green-700 bg-green-100' : safeStr(result.status) === 'Host is down' ? 'text-red-700 bg-red-100' : 'text-yellow-700 bg-yellow-100'}`}>
                                  {safeStr(result.status)}
                                </span>
                              </div>
                              <div className="space-y-2 text-sm">
                                <div className="flex justify-between items-center">
                                  <span className="text-gray-600">Scanned host</span>
                                  <span className="font-medium text-gray-900">{safeStr(result.scannedHost) || '—'}</span>
                                </div>
                                {displayHostname && (
                                  <div className="flex justify-between items-center">
                                    <span className="text-gray-600">Hostname</span>
                                    <span className="font-medium text-gray-900">{displayHostname}</span>
                                  </div>
                                )}
                                <div className="flex justify-between items-center pt-2 border-t border-gray-200">
                                  <span className="text-gray-600">Open ports</span>
                                  <span className="font-semibold text-gray-900">{result.openPortsCount != null ? Number(result.openPortsCount) : openCount}</span>
                                </div>
                                {portsList.length > 0 && (
                                  <div className="flex justify-between items-center text-gray-600">
                                    <span>Total scanned</span>
                                    <span>{portsList.length} (open: {openCount}, filtered: {filteredCount})</span>
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* All ports with state */}
                            {portsList.length > 0 && (
                              <div className="rounded-lg border border-gray-200 overflow-hidden">
                                <div className="bg-gray-100 px-4 py-2 border-b border-gray-200">
                                  <h4 className="text-sm font-semibold text-gray-800">Scanned ports (VPN-related)</h4>
                                </div>
                                <div className="bg-white divide-y divide-gray-100">
                                  {portsList.map(({ port, protocol, state, service }, idx) => (
                                    <div key={idx} className="flex items-center justify-between px-4 py-2.5 text-sm">
                                      <div className="flex items-center gap-3">
                                        <span className="font-mono font-medium text-gray-900">Port {port}</span>
                                        <span className="text-gray-500">({protocol})</span>
                                        {(service && service !== state && service !== 'open') && (
                                          <span className="text-gray-500">· {service}</span>
                                        )}
                                      </div>
                                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${state === 'open' ? 'bg-green-100 text-green-800' : state === 'filtered' ? 'bg-amber-100 text-amber-800' : 'bg-gray-100 text-gray-700'}`}>
                                        {state}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Note: Port meanings */}
                            <div className="rounded-lg border border-blue-200 bg-blue-50 overflow-hidden">
                              <div className="px-4 py-2 border-b border-blue-200 bg-blue-100">
                                <h4 className="text-sm font-semibold text-blue-900">Note: Meaning of scanned ports</h4>
                              </div>
                              <div className="divide-y divide-blue-100">
                                {[
                                  { port: '443', meaning: 'HTTPS / OpenVPN over TLS — often used for VPN to bypass firewalls' },
                                  { port: '500', meaning: 'IKE (Internet Key Exchange) — used by IPsec VPN' },
                                  { port: '4500', meaning: 'IKE NAT-T — IPsec VPN through NAT' },
                                  { port: '1194', meaning: 'OpenVPN — default port for OpenVPN' },
                                  { port: '1723', meaning: 'PPTP — Point-to-Point Tunneling Protocol (older VPN)' },
                                  { port: '1701', meaning: 'L2TP — Layer 2 Tunneling Protocol' },
                                ].map(({ port, meaning }) => (
                                  <div key={port} className="flex items-start gap-3 px-4 py-2.5 text-sm">
                                    <span className="font-mono font-medium text-blue-900 shrink-0">Port {port}</span>
                                    <span className="text-blue-800">{meaning}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </>
                        );
                      })()}

                      {result.error && (
                        <div className="bg-red-50 border border-red-200 rounded-md p-3">
                          <p className="text-sm text-red-700">
                            {typeof result.error === 'string' ? result.error : JSON.stringify(result.error)}
                          </p>
                        </div>
                      )}

                      {result.msg && !result.error && (
                        <div className="bg-blue-50 border border-blue-200 rounded-md p-3">
                          <p className="text-sm text-blue-700">
                            {typeof result.msg === 'string' ? result.msg : JSON.stringify(result.msg)}
                          </p>
                        </div>
                      )}
                    </div>
                  ) : ['qualityscore', 'ipsearch', 'checkip', 'checkonlinedata'].includes(method.id) ? (
                    <div className="space-y-3">
                      <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm font-medium text-gray-700">Result</span>
                          <span className={`text-sm font-semibold px-2 py-1 rounded ${
                            result.error ? 'text-red-700 bg-red-100' :
                            result.result === 1 || result.result === true ? 'text-yellow-700 bg-yellow-100' :
                            (result.result && typeof result.result === 'object' && (result.result.proxy || result.result.vpn)) ? 'text-yellow-700 bg-yellow-100' :
                            result.result === null && result.note ? 'text-gray-600 bg-gray-100' :
                            'text-green-700 bg-green-100'
                          }`}>
                            {getStatusText(result)}
                          </span>
                        </div>
                        {result.note && (
                          <p className="text-sm text-gray-600 mt-2 pt-2 border-t border-gray-200">{result.note}</p>
                        )}
                        {result.result && typeof result.result === 'object' && !Array.isArray(result.result) && method.id === 'qualityscore' && (
                          <div className="mt-3 pt-3 border-t border-gray-200 space-y-2 text-sm">
                            {result.result.torExit && (
                              <div className="flex justify-between"><span className="text-gray-600">Tor exit node</span><span className="font-medium text-red-600">Yes (High Risk)</span></div>
                            )}
                            <div className="flex justify-between"><span className="text-gray-600">Proxy</span><span className="font-medium">{result.result.proxy ? 'Yes' : 'No'}</span></div>
                            <div className="flex justify-between"><span className="text-gray-600">VPN</span><span className="font-medium">{result.result.vpn ? 'Yes' : 'No'}</span></div>
                            {result.result.fraud_score != null && (
                              <div className="flex justify-between"><span className="text-gray-600">Fraud score</span><span className="font-medium">{result.result.fraud_score}</span></div>
                            )}
                          </div>
                        )}
                      </div>
                      {result.error && (
                        <div className="bg-red-50 border border-red-200 rounded-md p-3">
                          <p className="text-sm text-red-700">{typeof result.error === 'string' ? result.error : JSON.stringify(result.error)}</p>
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

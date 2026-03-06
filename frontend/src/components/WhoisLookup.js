import React, { useState } from 'react';
import { Search, AlertCircle } from 'lucide-react';
import { whoisService } from '../services/api';

const WhoisLookup = () => {
  const [host, setHost] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!host.trim()) {
      setError('Please enter a hostname or IP address');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await whoisService.getRecord(host.trim());
      setResult(response);
    } catch (err) {
      if (err.isNetworkError) {
        setError('Network Error: Unable to connect to the server. Please ensure the backend is running on port 5000.');
      } else {
        setError(err.response?.data?.msg || err.message || 'An error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setHost('');
    setResult(null);
    setError(null);
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-gray-900 mb-2">WHOIS Lookup</h2>
        <p className="text-gray-600">
          Get detailed information about any domain or IP address including registration details, 
          hosting information, and DNS records.
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
                placeholder="e.g., google.com or 8.8.8.8"
                className="input-field pl-10"
                disabled={loading}
              />
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-5 w-5 text-gray-400" />
              </div>
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              type="submit"
              disabled={loading || !host.trim()}
              className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Looking up...' : 'Lookup WHOIS'}
            </button>
            <button
              type="button"
              onClick={handleClear}
              className="btn-secondary"
              disabled={loading}
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
              <AlertCircle className="h-5 w-5 text-red-400" />
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

      {/* Results */}
      {result && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">WHOIS Information</h3>
          <div className="space-y-5">
            {/* Domain */}
            {result.domain != null && result.domain !== '' && (
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="text-sm font-medium text-gray-600 shrink-0">Domain:</span>
                <span className="text-sm text-gray-900 break-all">{result.domain}</span>
              </div>
            )}

            {/* Registrant (nested object as readable rows) */}
            {result.registrant && typeof result.registrant === 'object' && Object.keys(result.registrant).length > 0 && (
              <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/50">
                <h4 className="text-sm font-semibold text-gray-800 mb-3">Registrant</h4>
                <div className="space-y-2">
                  {Object.entries(result.registrant).map(([k, v]) =>
                    v != null && v !== '' ? (
                      <div key={k} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                        <span className="text-sm text-gray-600 shrink-0 capitalize">{k.replace(/([A-Z])/g, ' $1').trim()}:</span>
                        <span className="text-sm text-gray-900 break-all">{String(v)}</span>
                      </div>
                    ) : null
                  )}
                </div>
              </div>
            )}

            {/* Hosting (nested object as readable rows) */}
            {result.hosting && typeof result.hosting === 'object' && Object.keys(result.hosting).length > 0 && (
              <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/50">
                <h4 className="text-sm font-semibold text-gray-800 mb-3">Hosting</h4>
                <div className="space-y-2">
                  {Object.entries(result.hosting).map(([k, v]) =>
                    v != null && v !== '' ? (
                      <div key={k} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                        <span className="text-sm text-gray-600 shrink-0 capitalize">{k.replace(/([A-Z])/g, ' $1').trim()}:</span>
                        <span className="text-sm text-gray-900 break-all">{String(v)}</span>
                      </div>
                    ) : null
                  )}
                </div>
              </div>
            )}

            {/* Registration (nested object as readable rows) */}
            {result.registration && typeof result.registration === 'object' && Object.keys(result.registration).length > 0 && (
              <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/50">
                <h4 className="text-sm font-semibold text-gray-800 mb-3">Registration</h4>
                <div className="space-y-2">
                  {Object.entries(result.registration).map(([k, v]) =>
                    v != null && v !== '' ? (
                      <div key={k} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                        <span className="text-sm text-gray-600 shrink-0 capitalize">{k.replace(/([A-Z])/g, ' $1').trim()}:</span>
                        <span className="text-sm text-gray-900 break-all">{String(v)}</span>
                      </div>
                    ) : null
                  )}
                </div>
              </div>
            )}

            {/* Other top-level fields (e.g. registrar, note) */}
            {['registrar', 'note', 'whoisError'].map((key) => {
              const value = result[key];
              if (value == null || value === '') return null;
              return (
                <div key={key} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                  <span className="text-sm font-medium text-gray-600 shrink-0 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}:</span>
                  <span className="text-sm text-gray-900 break-all">{String(value)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Help Text */}
      <div className="mt-8 bg-blue-50 border border-blue-200 rounded-md p-4">
        <h3 className="text-sm font-medium text-blue-800 mb-2">Tips:</h3>
        <ul className="text-sm text-blue-700 space-y-1">
          <li>• Enter domain names (e.g., google.com) or IP addresses (e.g., 8.8.8.8)</li>
          <li>• URLs with protocols are automatically processed</li>
          <li>• Invalid or suspicious inputs will be rejected for security</li>
          <li>• Results may take a few seconds to load</li>
        </ul>
      </div>
    </div>
  );
};

export default WhoisLookup;

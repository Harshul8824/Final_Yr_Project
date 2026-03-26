import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { Trash2, Clock, AlertTriangle, CheckCircle, Search } from 'lucide-react';
import { historyService } from '../services/api';

const History = () => {
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchHistory = async () => {
    setIsLoading(true);
    try {
      const data = await historyService.getMyHistory();
      setHistory(data);
    } catch (err) {
      toast.error(err.response?.data?.msg || err.message || 'Failed to fetch history');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleClearHistory = async () => {
    if (!window.confirm("Are you sure you want to clear your entire IP scan history?")) return;
    
    try {
      await historyService.clearHistory();
      toast.success('History cleared successfully');
      setHistory([]);
    } catch (err) {
      toast.error('Failed to clear history');
    }
  };

  const getRiskColor = (level) => {
    switch(level) {
        case 'High': return 'bg-red-100 text-red-800 border-red-200';
        case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
        case 'Low': return 'bg-green-100 text-green-800 border-green-200';
        default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const isVpnDetected = (results) => {
    // Determine overall VPN indicator by looking at results object
    if (!results) return false;
    if (results.qualityScore?.isVPN) return true;
    if (results.vpnListCheck?.result === 1) return true;
    if (results.onlineDataCheck?.result === 1) return true;
    return false;
  };

  const getThreatType = (results) => {
    if (!results) return 'None';
    if (results.onlineDataCheck?.threatType) return results.onlineDataCheck.threatType;
    if (results.qualityScore?.isTor) return 'Tor Node';
    if (results.qualityScore?.isProxy || results.localIPSearch?.result === 1) return 'Proxy';
    return '-';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12" style={{ minHeight: '60vh' }}>
        <div className="flex flex-col items-center">
          <div className="loading-spinner w-10 h-10 border-4 mb-4"></div>
          <p className="text-gray-500 font-medium">Fetching history...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-6xl p-4 md:p-6" style={{ minHeight: '85vh' }}>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2 flex items-center">
            <Clock className="w-8 h-8 mr-3 text-primary-600" />
            Check History
          </h1>
          <p className="text-gray-600">Review all your previous IP Address and VPN scans.</p>
        </div>
        
        {history.length > 0 && (
          <button 
            onClick={handleClearHistory} 
            className="btn-secondary text-red-600 hover:bg-red-50 hover:border-red-200 flex items-center shadow-sm"
          >
            <Trash2 className="w-4 h-4 mr-2" />
            Clear History
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <div className="card shadow-sm border border-gray-200 flex flex-col items-center justify-center p-16 bg-gray-50">
          <div className="bg-white p-5 rounded-full mb-6 shadow-sm border border-gray-100">
            <Search className="h-12 w-12 text-gray-300" />
          </div>
          <h3 className="text-xl font-bold text-gray-700 mb-2">No History Found</h3>
          <p className="text-gray-500 text-center max-w-md">
            You haven't scanned any IP addresses yet. Head over to the VPN Detection page to start scanning!
          </p>
        </div>
      ) : (
        <div className="card shadow-xl p-0 overflow-hidden border border-gray-100 bg-white" style={{ borderRadius: '1rem' }}>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">IP Address</th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Date & Time</th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">VPN/Proxy</th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Threat Type</th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Risk Level</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-100">
                {history.map((record) => {
                  const isVpn = isVpnDetected(record.results);
                  const threatTxt = getThreatType(record.results);
                  
                  return (
                    <tr key={record._id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono font-medium text-gray-900">
                        {record.ip}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(record.checkedAt).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isVpn ? (
                          <span className="inline-flex items-center text-red-600 font-medium text-sm">
                            <AlertTriangle className="w-4 h-4 mr-1.5" /> Yes
                          </span>
                        ) : (
                          <span className="inline-flex items-center text-green-600 font-medium text-sm">
                            <CheckCircle className="w-4 h-4 mr-1.5" /> No
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                        {threatTxt}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full border ${getRiskColor(record.overallRisk)}`}>
                          {record.overallRisk || 'Low'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default History;

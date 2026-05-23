import React, { useState, useRef } from 'react';
import toast from 'react-hot-toast';
import { Upload, FileText, CheckCircle, AlertTriangle, XCircle, Download, RefreshCw } from 'lucide-react';
import { batchProcessService } from '../services/api';

const BatchProcessing = () => {
  const [file, setFile] = useState(null);
  const [previewIps, setPreviewIps] = useState([]);
  const [totalIps, setTotalIps] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    const ext = selectedFile.name.split('.').pop().toLowerCase();
    if (ext !== 'txt' && ext !== 'csv') {
      toast.error('Only .txt and .csv files are allowed');
      return;
    }

    setFile(selectedFile);
    setResults(null);
    setProgress(0);

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      const lines = content.split(/\r?\n/).map(line => line.split(',')[0].trim()).filter(ip => ip.length > 0);
      
      setTotalIps(lines.length);
      setPreviewIps(lines.slice(0, 10));

      if (lines.length > 500) {
        toast.error('File contains more than 500 IPs. Maximum allowed is 500.');
        setFile(null);
      }
    };
    reader.readAsText(selectedFile);
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  const handleProcess = async () => {
    if (!file) return;
    
    setIsProcessing(true);
    setProgress(10);

    const progressInterval = setInterval(() => {
        setProgress(prev => prev >= 90 ? 90 : prev + 5);
    }, 500);

    try {
      const data = await batchProcessService.processFile(file);
      clearInterval(progressInterval);
      setProgress(100);
      setResults(data);
      toast.success(`Successfully processed ${data.length} IPs`);
    } catch (err) {
      clearInterval(progressInterval);
      setProgress(0);
      toast.error(err.response?.data?.msg || err.message || 'Failed to process file');
    } finally {
      setIsProcessing(false);
    }
  };

  const resetAll = () => {
    setFile(null);
    setResults(null);
    setPreviewIps([]);
    setTotalIps(0);
    setProgress(0);
  };

  const downloadCSV = () => {
    if (!results || results.length === 0) return;
    
    const headers = ['IP Address', 'VPN/Proxy Detected', 'Threat Type', 'Risk Level', 'Details'];
    const csvRows = [headers.join(',')];
    
    results.forEach(val => {
      const isVpnTxt = val.isVPN ? 'Yes' : 'No';
      const threatTxt = val.threatType || 'None';
      const row = [
        val.ip, 
        isVpnTxt, 
        threatTxt, 
        val.riskLevel, 
        `"${val.details.replace(/"/g, '""')}"`
      ];
      csvRows.push(row.join(','));
    });

    const csvData = csvRows.join('\n');
    const blob = new Blob([csvData], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'batch-scan-results.csv';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  const getRiskColor = (level) => {
    switch(level) {
        case 'High': return 'bg-red-100 text-red-800 border-red-200';
        case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
        case 'Low': return 'bg-green-100 text-green-800 border-green-200';
        default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="container mx-auto max-w-6xl p-4 md:p-6" style={{ minHeight: '85vh' }}>
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Batch Processing</h1>
        <p className="text-gray-600">Upload a list of IP addresses for bulk VPN and Threat analysis.</p>
      </div>

      <div className={`grid grid-cols-1 ${!results ? 'lg:grid-cols-3' : ''} gap-8`}>
        
        {/* Left Column: Upload & Preview */}
        {!results && (
          <div className="lg:col-span-1 space-y-6">
            <div className="card shadow-md p-6 border border-gray-200 bg-white" style={{ borderRadius: '1rem' }}>
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Upload File</h2>
              
              <input 
                type="file" 
                accept=".txt,.csv" 
                className="hidden" 
                ref={fileInputRef} 
                onChange={handleFileChange}
                disabled={isProcessing}
              />

              {!file ? (
                <div 
                  className="border-2 border-dashed border-gray-300 rounded-xl p-8 text-center cursor-pointer hover:bg-gray-50 transition-colors"
                  onClick={triggerFileInput}
                >
                  <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                  <p className="text-sm font-medium text-gray-700">Click to upload .txt or .csv</p>
                  <p className="text-xs text-gray-500 mt-2">Max 500 IPs per file</p>
                </div>
              ) : (
                <div className="border border-blue-200 bg-blue-50 rounded-xl p-6 relative">
                  <FileText className="h-8 w-8 text-blue-600 mb-2" />
                  <h3 className="text-sm font-bold text-gray-900 truncate" title={file.name}>{file.name}</h3>
                  <p className="text-xs text-gray-600 mt-1">{totalIps} IPs detected</p>
                  
                  {!isProcessing && !results && (
                    <button onClick={resetAll} className="absolute top-4 right-4 text-gray-400 hover:text-red-500">
                      <XCircle className="h-5 w-5" />
                    </button>
                  )}
                </div>
              )}

              {file && !results && (
                <div className="mt-6">
                  <button 
                    className="btn-primary w-full shadow-md" 
                    onClick={handleProcess} 
                    disabled={isProcessing}
                    style={{ padding: '0.75rem' }}
                  >
                    {isProcessing ? (
                      <span className="flex items-center justify-center">
                        <RefreshCw className="animate-spin -ml-1 mr-2 h-5 w-5" />
                        Processing...
                      </span>
                    ) : 'Start Batch Analysis'}
                  </button>
                </div>
              )}

              {isProcessing && (
                <div className="mt-6">
                  <div className="flex justify-between text-xs font-semibold text-gray-600 mb-2">
                    <span>Processing IPs</span>
                    <span>{progress}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2.5">
                    <div className="bg-blue-600 h-2.5 rounded-full transition-all duration-500 ease-out" style={{ width: `${progress}%` }}></div>
                  </div>
                </div>
              )}
            </div>

            {file && previewIps.length > 0 && !results && (
              <div className="card shadow-md p-6 border border-gray-200 bg-white" style={{ borderRadius: '1rem' }}>
                <h2 className="text-lg font-semibold text-gray-900 mb-4">File Preview</h2>
                <ul className="divide-y divide-gray-100">
                  {previewIps.map((ip, idx) => (
                    <li key={idx} className="py-2 text-sm text-gray-700 font-mono">{ip}</li>
                  ))}
                </ul>
                {totalIps > 10 && (
                  <p className="text-xs text-gray-500 mt-4 italic">And {totalIps - 10} more...</p>
                )}
              </div>
            )}
          </div>
        )}

        {/* Right Column: Results */}
        <div className={!results ? "lg:col-span-2" : "w-full"}>
          {results ? (
            <div className="card shadow-md p-0 overflow-hidden border border-gray-200 bg-white" style={{ borderRadius: '1rem' }}>
              <div className="p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                <h2 className="text-xl font-bold text-gray-900">Analysis Results</h2>
                <div className="space-x-4">
                  <button onClick={resetAll} className="btn-secondary text-sm">New Batch</button>
                  <button onClick={downloadCSV} className="btn-primary text-sm inline-flex items-center">
                    <Download className="w-4 h-4 mr-2" />
                    Export CSV
                  </button>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-white">
                    <tr>
                      <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">IP Address</th>
                      <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">VPN/Proxy</th>
                      <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Threat Type</th>
                      <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Risk Level</th>
                      <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Details</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-100">
                    {results.map((res, idx) => (
                      <tr key={idx} className="hover:bg-gray-50 transition-colors">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">{res.ip}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {res.isVPN ? (
                            <span className="inline-flex items-center text-red-600 font-medium text-sm">
                              <AlertTriangle className="w-4 h-4 mr-1" /> Yes
                            </span>
                          ) : (
                            <span className="inline-flex items-center text-green-600 font-medium text-sm">
                              <CheckCircle className="w-4 h-4 mr-1" /> No
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                          {res.threatType || '-'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full border ${getRiskColor(res.riskLevel)}`}>
                            {res.riskLevel}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600" style={{ maxWidth: '250px' }}>
                          <span className="truncate block" title={res.details}>{res.details}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
             <div className="h-full border-2 border-dashed border-gray-200 rounded-xl flex flex-col items-center justify-center p-12 text-gray-400 bg-gray-50">
               <div className="bg-white p-4 rounded-full mb-4 shadow-sm">
                 <FileText className="h-10 w-10 text-gray-300" />
               </div>
               <p className="text-lg font-medium text-gray-500">No results yet</p>
               <p className="text-sm mt-2 text-center">Upload a file and start the analysis to see results here.</p>
             </div>
          )}
        </div>

      </div>
    </div>
  );
};

export default BatchProcessing;

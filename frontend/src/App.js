import React, { useState } from 'react';
import { Toaster } from 'react-hot-toast';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import WhoisLookup from './components/WhoisLookup';
import VpnDetection from './components/VpnDetection';

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />;
      case 'whois':
        return <WhoisLookup />;
      case 'vpn-detection':
        return <VpnDetection />;
      case 'batch-process':
        return (
          <div className="max-w-4xl mx-auto p-6">
            <div className="text-center py-12">
              <h2 className="text-2xl font-bold text-gray-900 mb-4">Batch Processing</h2>
              <p className="text-gray-600 mb-8">Upload a file with multiple IPs for batch analysis.</p>
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
                <p className="text-yellow-800">This feature is coming soon!</p>
              </div>
            </div>
          </div>
        );
      case 'network-scan':
        return (
          <div className="max-w-4xl mx-auto p-6">
            <div className="text-center py-12">
              <h2 className="text-2xl font-bold text-gray-900 mb-4">Network Scanning</h2>
              <p className="text-gray-600 mb-8">Advanced network port scanning and analysis.</p>
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
                <p className="text-yellow-800">This feature is coming soon!</p>
              </div>
            </div>
          </div>
        );
      case 'analytics':
        return (
          <div className="max-w-4xl mx-auto p-6">
            <div className="text-center py-12">
              <h2 className="text-2xl font-bold text-gray-900 mb-4">Analytics</h2>
              <p className="text-gray-600 mb-8">Detailed analytics and reporting dashboard.</p>
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
                <p className="text-yellow-800">This feature is coming soon!</p>
              </div>
            </div>
          </div>
        );
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Header currentPage={currentPage} onPageChange={setCurrentPage} />
      <main className="py-6">
        {renderPage()}
      </main>
      
      {/* Toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
          success: {
            duration: 3000,
            iconTheme: {
              primary: '#4ade80',
              secondary: '#fff',
            },
          },
          error: {
            duration: 5000,
            iconTheme: {
              primary: '#ef4444',
              secondary: '#fff',
            },
          },
        }}
      />
    </div>
  );
}

export default App;

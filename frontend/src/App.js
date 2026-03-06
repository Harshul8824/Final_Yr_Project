import React, { useState } from 'react';
import { Toaster } from 'react-hot-toast';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import WhoisLookup from './components/WhoisLookup';
import VpnDetection from './components/VpnDetection';
import NetworkStatus from './components/NetworkStatus';
import Login from './components/Login';
import Register from './components/Register';
import { AuthProvider, useAuth } from './context/AuthContext';

function AppInner() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const { isAuthenticated, initializing } = useAuth();

  const safeSetPage = (next) => {
    // Protect VPN detection page behind login
    if (next === 'vpn-detection' && !isAuthenticated) {
      setCurrentPage('login');
      return;
    }
    setCurrentPage(next);
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />;
      case 'whois':
        return <WhoisLookup />;
      case 'vpn-detection':
        return <VpnDetection />;
      case 'login':
        return <Login onSuccess={() => safeSetPage('vpn-detection')} onGoRegister={() => safeSetPage('register')} />;
      case 'register':
        return <Register onSuccess={() => safeSetPage('vpn-detection')} onGoLogin={() => safeSetPage('login')} />;
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

  if (initializing) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="card">
          <div className="flex items-center">
            <div className="loading-spinner"></div>
            <span className="ml-3 text-gray-700">Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Header currentPage={currentPage} onPageChange={safeSetPage} />
      <main className="py-6">
        {renderPage()}
      </main>
      
      {/* Network Status */}
      <NetworkStatus />
      
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

function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}

export default App;

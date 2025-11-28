import React, { useState, useEffect } from 'react';
import { Wifi, WifiOff, AlertCircle } from 'lucide-react';

const NetworkStatus = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [backendStatus, setBackendStatus] = useState('checking');

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch('https://final-year-project-6v7g.onrender.com/api', {
          method: 'GET',
          timeout: 5000,
        });
        if (response.ok) {
          setBackendStatus('online');
        } else {
          setBackendStatus('error');
        }
      } catch (error) {
        setBackendStatus('offline');
      }
    };

    checkBackend();
    const interval = setInterval(checkBackend, 30000); // Check every 30 seconds

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const getStatusIcon = () => {
    if (!isOnline) {
      return <WifiOff className="h-4 w-4 text-red-500" />;
    }
    if (backendStatus === 'online') {
      return <Wifi className="h-4 w-4 text-green-500" />;
    }
    if (backendStatus === 'offline') {
      return <WifiOff className="h-4 w-4 text-red-500" />;
    }
    return <AlertCircle className="h-4 w-4 text-yellow-500" />;
  };

  const getStatusText = () => {
    if (!isOnline) {
      return 'No Internet Connection';
    }
    if (backendStatus === 'online') {
      return 'Backend Online';
    }
    if (backendStatus === 'offline') {
      return 'Backend Offline';
    }
    return 'Checking...';
  };

  const getStatusColor = () => {
    if (!isOnline || backendStatus === 'offline') {
      return 'text-red-600 bg-red-50 border-red-200';
    }
    if (backendStatus === 'online') {
      return 'text-green-600 bg-green-50 border-green-200';
    }
    return 'text-yellow-600 bg-yellow-50 border-yellow-200';
  };

  if (isOnline && backendStatus === 'online') {
    return null; // Don't show status if everything is working
  }

  return (
    <div className={`fixed top-4 right-4 z-50 p-3 rounded-lg border ${getStatusColor()}`}>
      <div className="flex items-center space-x-2">
        {getStatusIcon()}
        <span className="text-sm font-medium">{getStatusText()}</span>
      </div>
      {(!isOnline || backendStatus === 'offline') && (
        <div className="mt-2 text-xs">
          {!isOnline ? (
            <p>Please check your internet connection.</p>
          ) : (
            <p>Please ensure the backend server is running on port 5000.</p>
          )}
        </div>
      )}
    </div>
  );
};

export default NetworkStatus;


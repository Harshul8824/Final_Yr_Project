import React, { useState, useEffect } from 'react';
import { BarChart3, Shield, Search, FileText, Network, Activity } from 'lucide-react';
import { analyticsService } from '../services/api';

const Dashboard = () => {
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const data = await analyticsService.getAllAnalytics();
      setAnalytics(data);
    } catch (err) {
      setError(err.response?.data?.msg || err.message || 'Failed to fetch analytics');
    } finally {
      setLoading(false);
    }
  };

  // const stats = [
  //   {
  //     name: 'Total Data Points',
  //     value: analytics?.totalData || '0',
  //     icon: BarChart3,
  //     color: 'text-blue-600',
  //     bgColor: 'bg-blue-100',
  //   },
  //   {
  //     name: 'Training Data',
  //     value: analytics?.trainData || '0',
  //     icon: Activity,
  //     color: 'text-green-600',
  //     bgColor: 'bg-green-100',
  //   },
  //   {
  //     name: 'Test Data',
  //     value: analytics?.testData || '0',
  //     icon: BarChart3,
  //     color: 'text-purple-600',
  //     bgColor: 'bg-purple-100',
  //   },
  // ];

  const features = [
    {
      name: 'WHOIS Lookup',
      description: 'Get detailed domain and IP information',
      icon: Search,
      color: 'text-blue-600',
    },
    {
      name: 'VPN Detection',
      description: 'Comprehensive VPN and proxy detection',
      icon: Shield,
      color: 'text-red-600',
    },
    {
      name: 'Batch Processing',
      description: 'Process multiple IPs simultaneously',
      icon: FileText,
      color: 'text-green-600',
    },
    {
      name: 'Network Scanning',
      description: 'Advanced network port scanning',
      icon: Network,
      color: 'text-purple-600',
    },
  ];

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto p-6">
        <div className="flex items-center justify-center py-12">
          <div className="loading-spinner"></div>
          <span className="ml-2 text-gray-600">Loading dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Dashboard</h1>
        <p className="text-gray-600">
          Welcome to the VPN Detection System. Monitor analytics and access all security tools.
        </p>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
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

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {features.map((feature) => {
          const Icon = feature.icon;
          return (
            <div key={feature.name} className="card hover:shadow-lg transition-shadow duration-200">
              <div className="flex items-center mb-4">
                <Icon className={`h-8 w-8 ${feature.color} mr-3`} />
                <h3 className="text-lg font-semibold text-gray-900">{feature.name}</h3>
              </div>
              <p className="text-gray-600">{feature.description}</p>
            </div>
          );
        })}
      </div> 


      {/* Quick Actions */}
      <div className="mt-8 bg-gradient-to-r from-primary-50 to-blue-50 border border-primary-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <button className="btn-primary">
            <Search className="h-4 w-4 mr-2" />
            WHOIS Lookup
          </button>
          <button className="btn-primary">
            <Shield className="h-4 w-4 mr-2" />
            VPN Detection
          </button>
          <button className="btn-primary">
            <FileText className="h-4 w-4 mr-2" />
            Batch Process
          </button>
          <button className="btn-primary">
            <Network className="h-4 w-4 mr-2" />
            Network Scan
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

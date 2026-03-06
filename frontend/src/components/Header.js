import React from 'react';
import { Shield, Search, BarChart3, FileText, Network, LogIn, LogOut, UserPlus } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Header = ({ currentPage, onPageChange }) => {
  const { isAuthenticated, user, logout } = useAuth();

  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'whois', label: 'WHOIS Lookup', icon: Search },
    { id: 'vpn-detection', label: 'VPN Detection', icon: Shield },
    { id: 'batch-process', label: 'Batch Process', icon: FileText },
    { id: 'network-scan', label: 'Network Scan', icon: Network },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  ];

  return (
    <header style={{backgroundColor: 'white', boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.05)', borderBottom: '1px solid #e5e7eb'}}>
      <div style={{maxWidth: '80rem', margin: '0 auto', padding: '0 1rem'}}>
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: '4rem'}}>
          {/* Logo */}
          <div className="flex items-center">
            <div className="flex-shrink-0 flex items-center">
              <Shield className="h-8 w-8 text-primary-600" />
              <h1 className="ml-2 text-xl font-bold text-gray-900">
                VPN Detection System
              </h1>
            </div>
          </div>

          {/* Navigation */}
          <nav className="hidden md:flex items-center space-x-2">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => onPageChange(item.id)}
                  className={`inline-flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                    currentPage === item.id
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <Icon className="h-4 w-4 mr-2" />
                  {item.label}
                </button>
              );
            })}

            <div className="w-px h-6 bg-gray-200 mx-2" />

            {!isAuthenticated ? (
              <>
                <button
                  onClick={() => onPageChange('login')}
                  className={`inline-flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                    currentPage === 'login'
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <LogIn className="h-4 w-4 mr-2" />
                  Login
                </button>
                <button
                  onClick={() => onPageChange('register')}
                  className={`inline-flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                    currentPage === 'register'
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <UserPlus className="h-4 w-4 mr-2" />
                  Register
                </button>
              </>
            ) : (
              <>
                <span className="text-sm text-gray-600 px-2">
                  {user?.name || user?.email || 'User'}
                </span>
                <button
                  onClick={() => {
                    logout();
                    onPageChange('dashboard');
                  }}
                  className="inline-flex items-center px-3 py-2 rounded-md text-sm font-medium text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors duration-200"
                >
                  <LogOut className="h-4 w-4 mr-2" />
                  Logout
                </button>
              </>
            )}
          </nav>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              type="button"
              className="text-gray-600 hover:text-gray-900 focus:outline-none focus:text-gray-900"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      <div className="md:hidden">
        <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 bg-gray-50">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => onPageChange(item.id)}
                className={`w-full text-left flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                  currentPage === item.id
                    ? 'bg-primary-100 text-primary-700'
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {item.label}
              </button>
            );
          })}

          <div className="border-t border-gray-200 pt-2 mt-2">
            {!isAuthenticated ? (
              <>
                <button
                  onClick={() => onPageChange('login')}
                  className={`w-full text-left flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                    currentPage === 'login'
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <LogIn className="h-4 w-4 mr-2" />
                  Login
                </button>
                <button
                  onClick={() => onPageChange('register')}
                  className={`w-full text-left flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${
                    currentPage === 'register'
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <UserPlus className="h-4 w-4 mr-2" />
                  Register
                </button>
              </>
            ) : (
              <button
                onClick={() => {
                  logout();
                  onPageChange('dashboard');
                }}
                className="w-full text-left flex items-center px-3 py-2 rounded-md text-sm font-medium text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors duration-200"
              >
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;

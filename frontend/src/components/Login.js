import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { Shield } from 'lucide-react';

const Login = ({ onSuccess, onGoRegister }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login({ email: email.trim(), password });
      toast.success('Logged in successfully');
      onSuccess?.();
    } catch (err) {
      toast.error(err.response?.data?.msg || err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto p-4 flex flex-col items-center justify-center" style={{ minHeight: '85vh' }}>
      <div className="w-full max-w-md mx-auto">
        <div className="text-center mb-8 flex flex-col items-center">
          <div className="p-3 bg-white rounded-xl shadow-sm border border-gray-200 mb-6 inline-flex">
            <Shield className="h-10 w-10 text-primary-600" strokeWidth={1.5} />
          </div>
          <h2 className="text-3xl font-extrabold text-gray-900 tracking-tight mb-2">Sign in to your account</h2>
          <p className="text-gray-500 font-medium">VPN Detection System Enterprise</p>
        </div>

        <div className="card w-full p-8 shadow-xl bg-white" style={{ borderRadius: '1rem', border: '1px solid rgba(0,0,0,0.06)' }}>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Email address</label>
              <input
                className="input-field"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                autoComplete="email"
                required
                disabled={loading}
                style={{ padding: '0.75rem 1rem', fontSize: '0.95rem' }}
              />
            </div>
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Password</label>
              <input
                className="input-field"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                required
                disabled={loading}
                style={{ padding: '0.75rem 1rem', fontSize: '0.95rem', letterSpacing: '0.2em' }}
              />
            </div>
            
            <div className="pt-4">
              <button 
                className="btn-primary w-full shadow-md hover:shadow-lg transition-all" 
                disabled={loading} 
                style={{ width: '100%', padding: '0.85rem', fontSize: '1rem', fontWeight: '600' }}
              >
                {loading ? 'Authenticating...' : 'Sign In'}
              </button>
            </div>
          </form>
        </div>

        <div className="mt-8 text-center text-sm text-gray-500">
          Don&apos;t have an account?{' '}
          <button
            type="button"
            className="text-primary-600 font-bold hover:text-primary-700 transition-colors ml-1"
            onClick={() => onGoRegister?.()}
            disabled={loading}
          >
            Contact administrator
          </button>
        </div>
      </div>
    </div>
  );
};

export default Login;


import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';

const Register = ({ onSuccess, onGoLogin }) => {
  const { register } = useAuth();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await register({ name: name.trim(), email: email.trim(), password });
      toast.success('Account created');
      onSuccess?.();
    } catch (err) {
      toast.error(err.response?.data?.msg || err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto p-6">
      <div className="card">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Register</h2>
        <p className="text-gray-600 mb-6">Create an account to use VPN Detection features.</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
            <input
              className="input-field"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your name"
              autoComplete="name"
              required
              disabled={loading}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
            <input
              className="input-field"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
              required
              disabled={loading}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              className="input-field"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Minimum 6 characters"
              autoComplete="new-password"
              required
              minLength={6}
              disabled={loading}
            />
          </div>
          <button className="btn-primary w-full disabled:opacity-50" disabled={loading}>
            {loading ? 'Creating...' : 'Create account'}
          </button>
        </form>

        <div className="mt-4 text-sm text-gray-600">
          Already have an account?{' '}
          <button
            type="button"
            className="text-primary-700 font-medium hover:underline"
            onClick={() => onGoLogin?.()}
            disabled={loading}
          >
            Login
          </button>
        </div>
      </div>
    </div>
  );
};

export default Register;


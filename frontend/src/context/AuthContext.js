import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { authService } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(() => localStorage.getItem('auth_token') || '');
  const [user, setUser] = useState(null);
  const [initializing, setInitializing] = useState(true);

  useEffect(() => {
    const bootstrap = async () => {
      try {
        if (token) {
          const me = await authService.me();
          setUser(me.user || null);
        } else {
          setUser(null);
        }
      } catch (e) {
        // token invalid or backend down
        localStorage.removeItem('auth_token');
        setToken('');
        setUser(null);
      } finally {
        setInitializing(false);
      }
    };
    bootstrap();
  }, [token]);

  const login = async ({ email, password }) => {
    const res = await authService.login({ email, password });
    localStorage.setItem('auth_token', res.token);
    setToken(res.token);
    setUser(res.user || null);
    return res;
  };

  const register = async ({ name, email, password }) => {
    const res = await authService.register({ name, email, password });
    localStorage.setItem('auth_token', res.token);
    setToken(res.token);
    setUser(res.user || null);
    return res;
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    setToken('');
    setUser(null);
  };

  const value = useMemo(
    () => ({
      token,
      user,
      isAuthenticated: !!token && !!user,
      initializing,
      login,
      register,
      logout,
    }),
    [token, user, initializing]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};


import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../lib/models';
import { authApi } from '../api/auth';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (user: User) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  login: () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      const token = window.localStorage.getItem('cybog_token');
      if (token) {
        try {
          const response = await authApi.getMe();
          setUser(response.user);
        } catch (error) {
          // Token invalid or expired
          window.localStorage.removeItem('cybog_token');
          window.localStorage.removeItem('cybog_user');
          setUser(null);
        }
      }
      setLoading(false);
    };

    checkAuth();
  }, []);

  const handleLogin = (user: User) => {
    setUser(user);
  };

  const handleLogout = async () => {
    try {
      await authApi.logout();
    } catch (e) {
      console.error('Logout failed', e);
    }
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login: handleLogin, logout: handleLogout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

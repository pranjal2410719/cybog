import { axiosInstance } from './client';
import { User } from '../lib/models';

export interface LoginResponse {
  token: string;
  user: User;
}

export const authApi = {
  login: async (uid: string): Promise<LoginResponse> => {
    const response = await axiosInstance.post('/auth/login', { uid });
    return response.data;
  },
  
  getMe: async (): Promise<{ user: User }> => {
    const response = await axiosInstance.get('/auth/me');
    return response.data;
  },

  logout: async (): Promise<void> => {
    await axiosInstance.post('/auth/logout');
    window.localStorage.removeItem('cybog_token');
    window.localStorage.removeItem('cybog_user');
  }
};

import type { User, CreateUserDto, UpdateUserDto } from '../types/user.type';
import { api } from '@/lib/axios';

export const userService = {
  getAll: async (): Promise<User[]> => {
    const response = await api.get<User[]>('/users');
    return response.data;
  },

  getById: async (id: string): Promise<User> => {
    const response = await api.get<User>(`/users/${id}`);
    return response.data;
  },

  create: async (dto: CreateUserDto): Promise<User> => {
    const response = await api.post<User>('/users', dto);
    return response.data;
  },

  update: async (id: string, dto: UpdateUserDto): Promise<User> => {
    const response = await api.patch<User>(`/users/${id}`, dto);
    return response.data;
  },

  deactivate: async (id: string): Promise<User> => {
    const response = await api.patch<User>(`/users/${id}/deactivate`);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await api.delete<void>(`/users/${id}`);
  },
};
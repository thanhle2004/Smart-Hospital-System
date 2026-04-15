import type { User, CreateUserDto, UpdateUserDto } from '../types/user.type';

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    ...init,
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(error?.message ?? 'Request failed');
  }
  return res.json() as Promise<T>;
}

export const userService = {
  getAll: (): Promise<User[]> => request<User[]>('/users'),

  getById: (id: string): Promise<User> => request<User>(`/users/${id}`),

  create: (dto: CreateUserDto): Promise<User> =>
    request<User>('/users', {
      method: 'POST',
      body: JSON.stringify(dto),
    }),

  update: (id: string, dto: UpdateUserDto): Promise<User> =>
    request<User>(`/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(dto),
    }),

  deactivate: (id: string): Promise<User> =>
    request<User>(`/users/${id}/deactivate`, { method: 'PATCH' }),

  delete: (id: string): Promise<void> =>
    request<void>(`/users/${id}`, { method: 'DELETE' }),
};
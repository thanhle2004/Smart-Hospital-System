export type Role = 'ADMIN' | 'DOCTOR';

export interface UserProfile {
  id: string;
  userId: string;
  fullName?: string | null;
  avatarUrl?: string | null;
  bio?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface User {
  id: string;
  email: string;
  role: Role;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string | null;
  profile?: UserProfile | null;
}

export interface CreateUserDto {
  email: string;
  password: string;
  role?: Role;
  isActive?: boolean;
  profile?: {
    fullName?: string;
    avatarUrl?: string;
    bio?: string;
  };
}

export interface UpdateUserDto {
  email?: string;
  role?: Role;
  isActive?: boolean;
  fullName?: string;
  avatarUrl?: string;
  bio?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
}
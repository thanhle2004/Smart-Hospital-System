import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  MeResponse,
} from '../types/auth.type';
import { api } from '@/lib/axios';
import axios from 'axios';

const STATUS_MESSAGE_MAP: Record<number, string> = {
  400: 'The request is invalid. Please check your input and try again.',
  401: 'Incorrect email or password. Please try again.',
  403: 'You do not have permission to perform this action.',
  404: 'The requested resource was not found.',
  409: 'This data already exists. Please use a different value.',
  500: 'Server error. Please try again later.',
};

function mapErrorByStatus(status: number): string {
  return STATUS_MESSAGE_MAP[status] ?? `Request failed (${status}). Please try again.`;
}

function extractErrorMessage(body: unknown, status: number): string {
  const mappedByStatus = mapErrorByStatus(status);

  if (!body || typeof body !== 'object') {
    return mappedByStatus;
  }

  const maybeMessage = (body as { message?: unknown }).message;

  if (status === 401) {
    if (typeof maybeMessage === 'string' && maybeMessage.toLowerCase() === 'invalid credentials') {
      return mappedByStatus;
    }
  }

  if (typeof maybeMessage === 'string' && maybeMessage.trim()) {
    return maybeMessage;
  }

  if (Array.isArray(maybeMessage)) {
    const text = maybeMessage
      .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      .join(', ');

    if (text) {
      return text;
    }
  }

  const maybeError = (body as { error?: unknown }).error;
  if (typeof maybeError === 'string' && maybeError.trim()) {
    return maybeError;
  }

  return mappedByStatus;
}

function toErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;
    if (typeof status === 'number') {
      return extractErrorMessage(error.response?.data ?? null, status);
    }
  }

  return 'Request failed. Please try again.';
}

export const authService = {
  async login(payload: LoginRequest): Promise<LoginResponse> {
    try {
      const response = await api.post<LoginResponse>('/auth/login', payload);
      return response.data;
    } catch (error) {
      throw new Error(toErrorMessage(error));
    }
  },

  async register(payload: RegisterRequest): Promise<RegisterResponse> {
    try {
      const response = await api.post<RegisterResponse>('/auth/register', payload);
      return response.data;
    } catch (error) {
      throw new Error(toErrorMessage(error));
    }
  },

  async refresh(): Promise<LoginResponse> {
    try {
      const response = await api.post<LoginResponse>('/auth/refresh');
      return response.data;
    } catch (error) {
      throw new Error(toErrorMessage(error));
    }
  },

  async logout(): Promise<{ message: string }> {
    try {
      const response = await api.post<{ message: string }>('/auth/logout');
      return response.data;
    } catch (error) {
      throw new Error(toErrorMessage(error));
    }
  },

  async me(): Promise<MeResponse> {
    try {
      const response = await api.get<MeResponse>('/auth/me');
      return response.data;
    } catch (error) {
      throw new Error(toErrorMessage(error));
    }
  },

  async verifyPassword(password: string): Promise<{ verified: boolean }> {
    try {
      const response = await api.post<{ verified: boolean }>('/auth/verify-password', { password });
      return response.data;
    } catch (error) {
      throw new Error(toErrorMessage(error));
    }
  },
};
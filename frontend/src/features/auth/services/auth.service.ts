import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  MeResponse,
} from '../types/auth.type';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000';

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

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(extractErrorMessage(body, res.status));
  }
  return res.json() as Promise<T>;
}

export const authService = {
  async login(payload: LoginRequest): Promise<LoginResponse> {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    });
    return handleResponse<LoginResponse>(res);
  },

  async register(payload: RegisterRequest): Promise<RegisterResponse> {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    });
    return handleResponse<RegisterResponse>(res);
  },

  async refresh(): Promise<LoginResponse> {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    });
    return handleResponse<LoginResponse>(res);
  },

  async logout(): Promise<{ message: string }> {
    const res = await fetch(`${BASE_URL}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    });
    return handleResponse<{ message: string }>(res);
  },

  async me(): Promise<MeResponse> {
    const res = await fetch(`${BASE_URL}/auth/me`, {
      credentials: 'include',
    });
    return handleResponse<MeResponse>(res);
  },

  async verifyPassword(password: string): Promise<{ verified: boolean }> {
    const res = await fetch(`${BASE_URL}/auth/verify-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ password }),
    });
    return handleResponse<{ verified: boolean }>(res);
  },
};
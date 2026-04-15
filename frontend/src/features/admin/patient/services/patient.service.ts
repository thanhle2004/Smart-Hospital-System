import type {
  Patient,
  CreatePatientDto,
  UpdatePatientDto,
} from '../types/patient.type';

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

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const patientService = {
  getAll: (): Promise<Patient[]> => request<Patient[]>('/patient'),

  getById: (id: string): Promise<Patient> => request<Patient>(`/patient/${id}`),

  create: (dto: CreatePatientDto): Promise<Patient> =>
    request<Patient>('/patient', {
      method: 'POST',
      body: JSON.stringify(dto),
    }),

  update: (id: string, dto: UpdatePatientDto): Promise<Patient> =>
    request<Patient>(`/patient/${id}`, {
      method: 'PUT',
      body: JSON.stringify(dto),
    }),

  delete: (id: string): Promise<void> =>
    request<void>(`/patient/${id}`, { method: 'DELETE' }),
};

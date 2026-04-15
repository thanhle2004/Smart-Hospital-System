import {
  PatientType,
  CreatePatientTypePayload,
  UpdatePatientTypePayload,
} from '../types/patient-type.type';

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000';
const ENDPOINT = `${BASE_URL}/admin/patient-types`;

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const error = await res.json().catch(() => ({
      message: res.statusText,
    }));
    throw new Error(error?.message ?? 'Unable to process request');
  }
  return res.json() as Promise<T>;
}

// 👉 wrapper chung
async function fetchWithAuth(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

export const patientTypeService = {
  getAll(): Promise<PatientType[]> {
    return fetchWithAuth(ENDPOINT).then((r) =>
      handleResponse<PatientType[]>(r),
    );
  },

  getOne(id: number): Promise<PatientType> {
    return fetchWithAuth(`${ENDPOINT}/${id}`).then((r) =>
      handleResponse<PatientType>(r),
    );
  },

  create(payload: CreatePatientTypePayload): Promise<PatientType> {
    return fetchWithAuth(ENDPOINT, {
      method: 'POST',
      body: JSON.stringify(payload),
    }).then((r) => handleResponse<PatientType>(r));
  },

  update(
    id: number,
    payload: UpdatePatientTypePayload,
  ): Promise<PatientType> {
    return fetchWithAuth(`${ENDPOINT}/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }).then((r) => handleResponse<PatientType>(r));
  },

  remove(id: number): Promise<void> {
    return fetchWithAuth(`${ENDPOINT}/${id}`, {
      method: 'DELETE',
    }).then((r) => handleResponse<void>(r));
  },

  toggleActive(id: number): Promise<PatientType> {
    return fetchWithAuth(`${ENDPOINT}/${id}/toggle-active`, {
      method: 'PATCH',
    }).then((r) => handleResponse<PatientType>(r));
  },
};
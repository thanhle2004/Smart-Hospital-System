import { CreatePatientRequest, CreatePatientResponse } from '../types/profile-setup.type';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export async function createPatient(
  payload: CreatePatientRequest
): Promise<CreatePatientResponse> {
  const res = await fetch(`${API_URL}/patient`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let message = 'Failed to create patient';
    try {
      const data = await res.json();
      message = data.message || message;
    } catch {}
    throw new Error(message);
  }

  return res.json();
}
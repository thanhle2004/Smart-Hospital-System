import {
  PatientProfile,
  UpdatePatientProfileRequest,
} from '../types/patient-profile.type';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export async function fetchPatientProfile(): Promise<PatientProfile> {
  const res = await fetch(`${API_URL}/patient/me`, {
    credentials: 'include',
  });

  if (!res.ok) {
    throw new Error('Failed to load patient profile');
  }

  return res.json();
}

export async function updatePatientProfile(
  payload: UpdatePatientProfileRequest,
): Promise<PatientProfile> {
  const res = await fetch(`${API_URL}/patient/me`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let message = 'Failed to update patient profile';
    try {
      const data = await res.json();
      message = data?.message || message;
    } catch {}
    throw new Error(message);
  }

  return res.json();
}

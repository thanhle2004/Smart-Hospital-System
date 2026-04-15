import { Patient } from '../types/patient-dashboard.type';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export async function fetchCurrentPatient(): Promise<Patient> {
  const res = await fetch(`${API_URL}/patient/me`, {
    credentials: 'include',
  });

  if (!res.ok) {
    throw new Error('Failed to fetch patient');
  }

  return res.json();
}
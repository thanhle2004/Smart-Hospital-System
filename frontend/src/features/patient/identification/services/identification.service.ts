export interface CheckPhoneResponse {
  exists: boolean;
  patient?: {
    id: string;
  };
}

export async function checkPhone(phone: string): Promise<CheckPhoneResponse> {
  const res = await fetch('http://localhost:5000/patient/check-phone', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ phone }),
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }

  const data: CheckPhoneResponse = await res.json();
  return data;
}
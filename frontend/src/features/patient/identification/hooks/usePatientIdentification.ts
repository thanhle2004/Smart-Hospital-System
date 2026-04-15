'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';

import { checkPhone } from '../services/identification.service';

export function usePatientIdentification() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const identify = async (phone: string) => {
    try {
      setLoading(true);
      setError(null);

      const data = await checkPhone(phone);

      if (data.exists && data.patient) {
        router.push('/patient/dashboard');
      } else {
        router.push(`/patient/profile-setup?phone=${phone}`);
      }
    } catch (err) {
      setError('Server error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return { identify, loading, error };
}
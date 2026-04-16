'use client';

import { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

import { createPatient } from '../services/profile-setup.service';

export function useProfileSetup() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const phoneFromQuery = searchParams.get('phone') || '';

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone] = useState(phoneFromQuery);
  const [yearOfBirth, setYearOfBirth] = useState(1990);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!name || !phone) {
      setError('Please fill all required fields');
      return;
    }

    try {
      setLoading(true);
      setError('');

      const patient = await createPatient({
        name,
        email: email || undefined,
        phone,
        yearOfBirth,
      });

      router.push('/patient/dashboard');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return {
    name,
    setName,
    email,
    setEmail,
    phone,
    yearOfBirth,
    setYearOfBirth,
    submit,
    loading,
    error,
  };
}
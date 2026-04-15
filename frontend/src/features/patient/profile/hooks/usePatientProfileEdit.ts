'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  fetchPatientProfile,
  updatePatientProfile,
} from '../services/patient-profile.service';

export function usePatientProfileEdit() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [yearOfBirth, setYearOfBirth] = useState<number>(1990);
  const [patientId, setPatientId] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const profile = await fetchPatientProfile();
        setPatientId(profile.id);
        setName(profile.name);
        setEmail(profile.email ?? '');
        setPhone(profile.phone);
        setYearOfBirth(profile.yearOfBirth);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load profile');
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  const submit = async () => {
    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    setSubmitting(true);
    setError('');
    try {
      await updatePatientProfile({
        name: name.trim(),
        email: email.trim() || undefined,
        yearOfBirth,
      });
      router.push('/patient/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update profile');
    } finally {
      setSubmitting(false);
    }
  };

  return {
    patientId,
    loading,
    submitting,
    error,
    name,
    email,
    phone,
    yearOfBirth,
    setName,
    setEmail,
    setYearOfBirth,
    submit,
    backToDashboard: () => {
      router.push('/patient/dashboard');
    },
  };
}

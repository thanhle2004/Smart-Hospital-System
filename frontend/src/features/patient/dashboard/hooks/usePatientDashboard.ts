'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

import { fetchCurrentPatient } from '../services/patient-dashboard.service';
import { Patient } from '../types/patient-dashboard.type';

export function usePatientDashboard() {
  const router = useRouter();

  const [patient, setPatient] = useState<Patient | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchCurrentPatient();
        setPatient(data);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  const goToServiceSelection = () => {
    if (patient) {
      router.push(`/patient/service-selection?patientId=${patient.id}`);
    }
  };

  const goToMedicalRecords = () => {
    router.push('/patient/medical-records');
  };

  const goToEditProfile = () => {
    router.push('/patient/profile');
  };

  return {
    patientId: patient?.id ?? null,
    patient,
    loading,
    error,
    goToServiceSelection,
    goToMedicalRecords,
    goToEditProfile,
  };
}
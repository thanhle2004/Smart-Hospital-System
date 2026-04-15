'use client';

import { useState, useEffect, useCallback } from 'react';
import { patientService } from '../services/patient.service';
import type {
  Patient,
  CreatePatientDto,
  UpdatePatientDto,
} from '../types/patient.type';

export function usePatients() {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPatients = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await patientService.getAll();
      setPatients(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch patients');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPatients();
  }, [fetchPatients]);

  const createPatient = useCallback(async (dto: CreatePatientDto): Promise<Patient> => {
    const created = await patientService.create(dto);
    setPatients((prev) => [created, ...prev]);
    return created;
  }, []);

  const updatePatient = useCallback(
    async (id: string, dto: UpdatePatientDto): Promise<Patient> => {
      const updated = await patientService.update(id, dto);
      setPatients((prev) => prev.map((p) => (p.id === id ? updated : p)));
      return updated;
    },
    [],
  );

  const deletePatient = useCallback(async (id: string): Promise<void> => {
    await patientService.delete(id);
    setPatients((prev) => prev.filter((p) => p.id !== id));
  }, []);

  return {
    patients,
    isLoading,
    error,
    refetch: fetchPatients,
    createPatient,
    updatePatient,
    deletePatient,
  };
}

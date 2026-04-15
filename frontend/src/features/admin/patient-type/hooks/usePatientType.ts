'use client';

import { useState, useEffect, useCallback } from 'react';
import { patientTypeService } from '../services/patient-type.service';
import {
  PatientType,
  CreatePatientTypePayload,
  UpdatePatientTypePayload,
} from '../types/patient-type.type';
import { toast } from 'sonner';

export function usePatientTypes() {
  const [patientTypes, setPatientTypes] = useState<PatientType[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await patientTypeService.getAll();
      setPatientTypes(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unable to load patient types';
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const create = useCallback(
    async (payload: CreatePatientTypePayload): Promise<boolean> => {
      try {
        const created = await patientTypeService.create(payload);
        setPatientTypes((prev) => [created, ...prev]);
        toast.success(`Patient type created: "${created.name}"`);
        return true;
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Error creating patient type';
        toast.error(msg);
        return false;
      }
    },
    [],
  );

  const update = useCallback(
    async (id: number, payload: UpdatePatientTypePayload): Promise<boolean> => {
      try {
        const updated = await patientTypeService.update(id, payload);
        setPatientTypes((prev) =>
          prev.map((pt) => (pt.id === id ? updated : pt)),
        );
        toast.success(`Patient type updated: "${updated.name}"`);
        return true;
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Error updating patient type';
        toast.error(msg);
        return false;
      }
    },
    [],
  );

  const remove = useCallback(async (id: number): Promise<boolean> => {
    try {
      await patientTypeService.remove(id);
      setPatientTypes((prev) => prev.filter((pt) => pt.id !== id));
      toast.success('Patient type deleted successfully');
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Error deleting patient type';
      toast.error(msg);
      return false;
    }
  }, []);

  const toggleActive = useCallback(async (id: number): Promise<void> => {
    try {
      const updated = await patientTypeService.toggleActive(id);
      setPatientTypes((prev) =>
        prev.map((pt) => (pt.id === id ? updated : pt)),
      );
      toast.success(
        `${updated.isActive ? 'Active' : 'Inactive'} "${updated.name}"`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Error toggling patient type status';
      toast.error(msg);
    }
  }, []);

  return {
    patientTypes,
    isLoading,
    error,
    refetch: fetchAll,
    create,
    update,
    remove,
    toggleActive,
  };
}
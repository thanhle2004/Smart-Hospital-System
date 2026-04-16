import type {
  Patient,
  CreatePatientDto,
  UpdatePatientDto,
} from '../types/patient.type';
import { api } from '@/lib/axios';

export const patientService = {
  getAll: async (): Promise<Patient[]> => {
    const response = await api.get<Patient[]>('/patient');
    return response.data;
  },

  getById: async (id: string): Promise<Patient> => {
    const response = await api.get<Patient>(`/patient/${id}`);
    return response.data;
  },

  create: async (dto: CreatePatientDto): Promise<Patient> => {
    const response = await api.post<Patient>('/patient', dto);
    return response.data;
  },

  update: async (id: string, dto: UpdatePatientDto): Promise<Patient> => {
    const response = await api.put<Patient>(`/patient/${id}`, dto);
    return response.data;
  },

  delete: async (id: string): Promise<void> => {
    await api.delete<void>(`/patient/${id}`);
  },
};

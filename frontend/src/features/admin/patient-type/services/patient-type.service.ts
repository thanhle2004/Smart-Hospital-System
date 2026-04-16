import {
  PatientType,
  CreatePatientTypePayload,
  UpdatePatientTypePayload,
} from '../types/patient-type.type';
import { api } from '@/lib/axios';

const ENDPOINT = '/admin/patient-types';

export const patientTypeService = {
  async getAll(): Promise<PatientType[]> {
    const response = await api.get<PatientType[]>(ENDPOINT);
    return response.data;
  },

  async getOne(id: number): Promise<PatientType> {
    const response = await api.get<PatientType>(`${ENDPOINT}/${id}`);
    return response.data;
  },

  async create(payload: CreatePatientTypePayload): Promise<PatientType> {
    const response = await api.post<PatientType>(ENDPOINT, payload);
    return response.data;
  },

  async update(
    id: number,
    payload: UpdatePatientTypePayload,
  ): Promise<PatientType> {
    const response = await api.patch<PatientType>(`${ENDPOINT}/${id}`, payload);
    return response.data;
  },

  async remove(id: number): Promise<void> {
    await api.delete<void>(`${ENDPOINT}/${id}`);
  },

  async toggleActive(id: number): Promise<PatientType> {
    const response = await api.patch<PatientType>(`${ENDPOINT}/${id}/toggle-active`);
    return response.data;
  },
};
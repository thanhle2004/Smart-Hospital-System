export interface PatientType {
  id: number;
  code: string;
  name: string;
  description?: string | null;
  basePriority?: number | null;
  isActive: boolean;
}

export interface CreatePatientTypePayload {
  code: string;
  name: string;
  description?: string;
  basePriority?: number;
  isActive?: boolean;
}

export interface UpdatePatientTypePayload extends Partial<CreatePatientTypePayload> {}
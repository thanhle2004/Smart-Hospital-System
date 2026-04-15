export interface PatientTypeRef {
  id: number;
  name: string;
}

export interface Patient {
  id: string;
  name: string;
  email?: string | null;
  phone: string;
  yearOfBirth: number;
  patientTypeId: number;
  patientType?: PatientTypeRef | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreatePatientDto {
  name: string;
  email?: string;
  phone: string;
  yearOfBirth: number;
  patientTypeId: number;
}

export interface UpdatePatientDto extends Partial<CreatePatientDto> {}

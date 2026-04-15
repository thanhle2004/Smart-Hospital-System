export interface PatientProfile {
  id: string;
  name: string;
  email?: string | null;
  phone: string;
  yearOfBirth: number;
  patientTypeId: number;
}

export interface UpdatePatientProfileRequest {
  name: string;
  email?: string;
  yearOfBirth: number;
}

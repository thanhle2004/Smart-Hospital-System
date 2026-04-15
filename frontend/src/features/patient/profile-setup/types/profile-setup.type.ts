export interface CreatePatientRequest {
  name: string;
  email?: string;
  phone: string;
  yearOfBirth: number;
  patientTypeId: number;
}

export interface CreatePatientResponse {
  id: string;
}
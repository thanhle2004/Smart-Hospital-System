export interface CreatePatientRequest {
  name: string;
  email?: string;
  phone: string;
  yearOfBirth: number;
}

export interface CreatePatientResponse {
  id: string;
}
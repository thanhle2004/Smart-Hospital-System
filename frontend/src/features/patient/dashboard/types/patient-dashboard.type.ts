export interface Patient {
  id: string;
  name: string;
  phone: string;
  email?: string | null;
  yearOfBirth: number;
  patientTypeId: number;
}
import { z } from 'zod';

export const createPatientSchema = z.object({
  name: z.string().min(1),
  email: z.email().optional(),
  phone: z.string().min(1),
  yearOfBirth: z.number().int().min(1900).max(new Date().getFullYear()),
  patientTypeId: z.number().int().optional(),
});

export type CreatePatientDto = z.infer<typeof createPatientSchema>;

import { z } from 'zod';
import { createPatientSchema } from './create-patient.dto';

export const updatePatientSchema = createPatientSchema.partial();

export type UpdatePatientDto = z.infer<typeof updatePatientSchema>;
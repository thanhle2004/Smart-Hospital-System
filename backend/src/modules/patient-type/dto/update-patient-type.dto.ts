import { z } from 'zod';
import { createPatientTypeSchema } from './create-patient-type.dto';

export const updatePatientTypeSchema = createPatientTypeSchema.partial();

export type UpdatePatientTypeDto = z.infer<typeof updatePatientTypeSchema>;
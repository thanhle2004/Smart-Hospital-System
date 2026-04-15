import { z } from 'zod';

export const createPatientTypeSchema = z.object({
  code: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  basePriority: z.number().int().min(0).optional(),
  isActive: z.boolean().optional(),
});

export type CreatePatientTypeDto = z.infer<typeof createPatientTypeSchema>;
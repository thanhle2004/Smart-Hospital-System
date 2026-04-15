import { z } from 'zod';

export const createRegisterSchema = z.object({
  email: z.email(),
  password: z.string().min(6),
  role: z.enum(['ADMIN', 'DOCTOR']).optional().default('DOCTOR'),
});

export type CreateRegisterDto = z.infer<typeof createRegisterSchema>;
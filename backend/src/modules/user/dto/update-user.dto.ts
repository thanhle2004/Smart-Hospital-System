import { z } from 'zod';

export const updateUserSchema = z.object({
  email: z.email().optional(),
  role: z.enum(['ADMIN', 'DOCTOR']).optional(),
  isActive: z.boolean().optional(),
  fullName: z.string().optional(),
  avatarUrl: z.string().url().optional(),
  bio: z.string().optional(),
});

export type UpdateUserDto = z.infer<typeof updateUserSchema>;
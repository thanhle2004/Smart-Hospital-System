import { z } from 'zod';

const userProfileInputSchema = z.object({
  fullName: z.string().min(1).optional(),
  avatarUrl: z.string().url().optional(),
  bio: z.string().optional(),
});

export const createUserSchema = z.object({
  email: z.email(),
  password: z.string().min(6),
  role: z.enum(['ADMIN', 'DOCTOR']).optional().default('DOCTOR'),
  isActive: z.boolean().optional().default(true),
  profile: userProfileInputSchema.optional(),
});

export type CreateUserDto = z.infer<typeof createUserSchema>;
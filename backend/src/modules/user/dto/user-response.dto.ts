import { z } from 'zod';

export const userProfileResponseSchema = z.object({
  id: z.string(),
  userId: z.string(),
  fullName: z.string().nullable().optional(),
  avatarUrl: z.string().nullable().optional(),
  bio: z.string().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export const userResponseSchema = z.object({
  id: z.string(),
  email: z.email(),
  role: z.enum(['ADMIN', 'DOCTOR']),
  isActive: z.boolean(),
  createdAt: z.date(),
  updatedAt: z.date(),
  lastLoginAt: z.date().nullable().optional(),
  profile: userProfileResponseSchema.nullable().optional(),
});

export type UserResponseDto = z.infer<typeof userResponseSchema>;
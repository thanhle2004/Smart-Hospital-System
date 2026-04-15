import { z } from 'zod';

// Shared schema for responses that return user information
export const userResponseSchema = z.object({
  id: z.string(),
  email: z.email(),
  role: z.string(),
  createdAt: z.date().optional(),
});

// Schema for Login/Register responses (includes token)
export const authResponseSchema = z.object({
  user: userResponseSchema, 
  accessToken: z.string(),
  refreshToken: z.string(),
});

export type UserResponseDto = z.infer<typeof userResponseSchema>;
export type AuthResponseDto = z.infer<typeof authResponseSchema>;
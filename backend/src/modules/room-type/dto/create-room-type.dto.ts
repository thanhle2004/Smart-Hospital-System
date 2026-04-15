import { z } from 'zod';

export const createRoomTypeSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  avgProcessTime: z
    .number()
    .int()
    .positive("Average processing time must be a positive integer (in minutes)"),
  defaultCapacity: z.number().int().positive(),
});

export type CreateRoomTypeDto = z.infer<typeof createRoomTypeSchema>;
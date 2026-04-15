import { z } from 'zod';

export const baseRoomSchema = z.object({
  name: z
    .string()
    .min(1, "Name is required")
    .trim(),

  roomNumber: z
    .number()
    .int()
    .positive("Room number must be a positive integer"),

  capacity: z
    .number()
    .int()
    .nonnegative("Capacity must be greater than or equal to 0")
    .optional(),

  roomTypeId: z
    .number()
    .int()
    .positive("Room type ID must be a positive integer")
    .nullable()
    .optional(),

  avgProcessTime: z
    .number()
    .int()
    .nonnegative("Average processing time must be greater than or equal to 0")
    .default(0),
});

export const createRoomSchema = baseRoomSchema.superRefine((data, ctx) => {
  if (data.roomTypeId != null && data.avgProcessTime <= 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['avgProcessTime'],
      message:
        'Average processing time is required and must be greater than 0 when room type is selected',
    });
  }
});

export type CreateRoomDto = z.infer<typeof createRoomSchema>;
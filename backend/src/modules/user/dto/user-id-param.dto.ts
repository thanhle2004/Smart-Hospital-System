import { z } from 'zod';

export const userIdParamSchema = z.object({
  id: z.uuid(),
});

export type UserIdParamDto = z.infer<typeof userIdParamSchema>;
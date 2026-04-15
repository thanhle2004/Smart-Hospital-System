import { z } from 'zod';

// Flow update only allows changing name.
export const updateFlowSchema = z.object({
  name: z.string().min(1).optional(),
});

export type UpdateFlowDto = z.infer<typeof updateFlowSchema>;
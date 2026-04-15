import { z } from 'zod';

export const createVisitFlowSchema = z.object({
    visitId: z.string().min(1),
    roomTypeId: z.number().int(),
    orderIndex: z.number().int().optional(),
    requiredVisitFlowIds: z.array(z.number().int()).optional(),
});

export type CreateVisitFlowDto = z.infer<typeof createVisitFlowSchema>;
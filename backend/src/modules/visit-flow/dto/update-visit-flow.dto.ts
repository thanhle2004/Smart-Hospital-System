import { z } from 'zod';
import { createVisitFlowSchema } from './create-visit-flow.dto';

export const updateVisitFlowSchema = createVisitFlowSchema
    .partial()
    .extend({
        isSkipped: z.boolean().optional(),
    });

export type UpdateVisitFlowDto = z.infer<typeof updateVisitFlowSchema>;

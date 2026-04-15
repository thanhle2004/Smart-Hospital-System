import { z } from 'zod';
import { createPriorityRuleSchema } from './create-priority-rule.dto';

export const updatePriorityRuleSchema = createPriorityRuleSchema.partial();

export type UpdatePriorityRuleDto = z.infer<typeof updatePriorityRuleSchema>;

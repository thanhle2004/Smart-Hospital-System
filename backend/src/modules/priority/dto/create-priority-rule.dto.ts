import { z } from 'zod';

export const createPriorityRuleSchema = z.object({
  ruleName: z.string().min(1),
  minAge: z.number().int().min(0).optional(),
  maxAge: z.number().int().min(0).optional(),
  patientTypeId: z.number().int().optional(),
  isEmergency: z.boolean().optional(),
  priorityValue: z.number().int().positive(),
  applyOrder: z.number().int().min(0).optional(),
  isActive: z.boolean().optional(),
});

export type CreatePriorityRuleDto = z.infer<typeof createPriorityRuleSchema>;
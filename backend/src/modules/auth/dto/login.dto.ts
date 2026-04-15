import { z } from 'zod';

export const createLoginSchema = z.object({
    email: z.email(),
    password: z.string(),
});

export type CreateLoginDto = z.infer<typeof createLoginSchema>;
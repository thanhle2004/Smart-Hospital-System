import { z } from 'zod';

const envSchema = z.object({
  // Environment
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  DATABASE_URL: z.url(),

  // JWT Config
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),

  // Cookie Config
  COOKIE_ACCESS: z.string().default('access_token'),
  COOKIE_REFRESH: z.string().default('refresh_token'),
});

export const env = envSchema.parse(process.env);
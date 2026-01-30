/**
 * Configuration for standalone MCP server
 * Loaded from environment variables
 */

import { z } from "zod";

const ConfigSchema = z.object({
  // Server settings
  PORT: z.coerce.number().default(3000),
  HOST: z.string().default("0.0.0.0"),

  // Brain API (required)
  ARGUS_BRAIN_URL: z.string().url().default("http://localhost:8000"),
  API_TOKEN: z.string().optional(),

  // Browser Pool
  BROWSER_POOL_URL: z.string().url().optional(),
  BROWSER_POOL_JWT_SECRET: z.string().optional(),

  // Storage (MinIO/S3)
  STORAGE_PROVIDER: z.enum(["minio", "s3", "local"]).default("minio"),
  MINIO_ENDPOINT: z.string().default("localhost:9000"),
  MINIO_ACCESS_KEY: z.string().default("minioadmin"),
  MINIO_SECRET_KEY: z.string().default("minioadmin"),
  MINIO_BUCKET: z.string().default("argus-artifacts"),
  MINIO_SECURE: z.coerce.boolean().default(false),
  MINIO_REGION: z.string().default("us-east-1"),

  // Redis (for session state)
  REDIS_URL: z.string().default("redis://localhost:6379"),

  // Security
  JWT_SECRET: z.string().optional(),
  CORS_ORIGINS: z.string().default("*"),

  // Logging
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
});

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(): Config {
  const env = process.env;

  return ConfigSchema.parse({
    PORT: env.PORT,
    HOST: env.HOST,
    ARGUS_BRAIN_URL: env.ARGUS_BRAIN_URL,
    API_TOKEN: env.API_TOKEN,
    BROWSER_POOL_URL: env.BROWSER_POOL_URL,
    BROWSER_POOL_JWT_SECRET: env.BROWSER_POOL_JWT_SECRET,
    STORAGE_PROVIDER: env.STORAGE_PROVIDER,
    MINIO_ENDPOINT: env.MINIO_ENDPOINT,
    MINIO_ACCESS_KEY: env.MINIO_ACCESS_KEY,
    MINIO_SECRET_KEY: env.MINIO_SECRET_KEY,
    MINIO_BUCKET: env.MINIO_BUCKET,
    MINIO_SECURE: env.MINIO_SECURE,
    MINIO_REGION: env.MINIO_REGION,
    REDIS_URL: env.REDIS_URL,
    JWT_SECRET: env.JWT_SECRET,
    CORS_ORIGINS: env.CORS_ORIGINS,
    LOG_LEVEL: env.LOG_LEVEL,
  });
}

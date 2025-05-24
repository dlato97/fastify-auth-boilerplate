import { z } from 'zod'
import dotenv from 'dotenv'

// Load environment variables
dotenv.config()

const configSchema = z.object({
  // Environment
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Server
  PORT: z.coerce.number().min(1).max(65535).default(3000),
  HOST: z.string().default('localhost'),
  CORS_ORIGIN: z.string().default('http://localhost:3000,http://localhost:5173'),

  // Database
  DATABASE_URL: z.string().url(),

  // Redis
  REDIS_URL: z.string().url(),

  // JWT
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // Rate Limiting
  RATE_LIMIT_MAX: z.coerce.number().positive().default(100),
  RATE_LIMIT_WINDOW: z.string().default('1m'),

  // Email
  SMTP_HOST: z.string(),
  SMTP_PORT: z.coerce.number().min(1).max(65535),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().email(),
  SMTP_FROM_NAME: z.string(),

  // Application URLs
  APP_URL: z.string().url(),
  FRONTEND_URL: z.string().url(),

  // Security
  BCRYPT_ROUNDS: z.coerce.number().min(10).max(20).default(12),
  SESSION_SECRET: z.string().min(32),

  // Features
  ENABLE_2FA: z.coerce.boolean().default(true),
  ENABLE_EMAIL_VERIFICATION: z.coerce.boolean().default(true),
  ENABLE_PASSWORD_RESET: z.coerce.boolean().default(true),
  ENABLE_AUDIT_LOGS: z.coerce.boolean().default(true),
  SWAGGER_ENABLED: z.coerce.boolean().default(true),

  // File Upload
  MAX_FILE_SIZE: z.coerce.number().positive().default(10485760), // 10MB
  UPLOAD_DIR: z.string().default('uploads'),

  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  ENABLE_REQUEST_LOGGING: z.coerce.boolean().default(true)
})

const parsedEnv = configSchema.safeParse(process.env)

if (!parsedEnv.success) {
  console.error('❌ Invalid environment variables:')
  console.error(parsedEnv.error.format())
  process.exit(1)
}

const env = parsedEnv.data

export const config = {
  // Environment
  isDevelopment: env.NODE_ENV === 'development',
  isProduction: env.NODE_ENV === 'production',
  isTest: env.NODE_ENV === 'test',

  // Server configuration
  server: {
    port: env.PORT,
    host: env.HOST,
    corsOrigins: env.CORS_ORIGIN.split(',').map(origin => origin.trim()),
    maxBodySize: env.MAX_FILE_SIZE
  },

  // Database
  database: {
    url: env.DATABASE_URL
  },

  // Redis
  redis: {
    url: env.REDIS_URL
  },

  // JWT configuration
  jwt: {
    accessSecret: env.JWT_ACCESS_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    accessExpiresIn: env.JWT_ACCESS_EXPIRES_IN,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN
  },

  // Rate limiting
  rateLimit: {
    max: env.RATE_LIMIT_MAX,
    timeWindow: env.RATE_LIMIT_WINDOW
  },

  // Email configuration
  email: {
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    user: env.SMTP_USER,
    pass: env.SMTP_PASS,
    from: env.SMTP_FROM,
    fromName: env.SMTP_FROM_NAME
  },

  // Application URLs
  urls: {
    app: env.APP_URL,
    frontend: env.FRONTEND_URL
  },

  // Security
  security: {
    bcryptRounds: env.BCRYPT_ROUNDS,
    sessionSecret: env.SESSION_SECRET
  },

  // Feature flags
  features: {
    twoFactor: env.ENABLE_2FA,
    emailVerification: env.ENABLE_EMAIL_VERIFICATION,
    passwordReset: env.ENABLE_PASSWORD_RESET,
    auditLogs: env.ENABLE_AUDIT_LOGS,
    swagger: env.SWAGGER_ENABLED
  },

  // File upload
  upload: {
    maxFileSize: env.MAX_FILE_SIZE,
    uploadDir: env.UPLOAD_DIR
  },

  // Logging
  logging: {
    level: env.LOG_LEVEL,
    enableRequestLogging: env.ENABLE_REQUEST_LOGGING
  }
} as const

// Type export for use in other files
export type Config = typeof config

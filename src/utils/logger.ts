import pino from 'pino'
import { config } from '@/config/config.js'

// Create base logger
export const logger = pino({
  level: config.logging.level,
  ...(config.isDevelopment
    ? {
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
            singleLine: false,
            hideObject: false,
            customPrettifiers: {
              // level: (logLevel: string) => `LEVEL: ${logLevel}`,
              // time: (timestamp: string) => `🕐 ${timestamp}`
            }
          }
        }
      }
    : {
        formatters: {
          level: (label: string) => ({ level: label }),
          log: (object: Record<string, any>) => {
            // Add common fields in production
            return {
              ...object,
              environment: config.isDevelopment ? 'development' : 'production',
              service: 'fastify-auth-api',
              version: process.env.npm_package_version || '1.0.0'
            }
          }
        }
      })
})

// Child loggers for different modules
export const createLogger = (module: string) => {
  return logger.child({ module })
}

// Specialized loggers
export const authLogger = createLogger('auth')
export const dbLogger = createLogger('database')
export const emailLogger = createLogger('email')
export const auditLogger = createLogger('audit')

// Utility functions for structured logging
export const logRequest = (request: any, additionalData?: Record<string, any>) => {
  logger.info(
    {
      requestId: request.id,
      method: request.method,
      url: request.url,
      userAgent: request.headers['user-agent'],
      ip: request.ip,
      ...additionalData
    },
    'HTTP Request'
  )
}

export const logResponse = (request: any, reply: any, additionalData?: Record<string, any>) => {
  logger.info(
    {
      requestId: request.id,
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime: reply.getResponseTime(),
      ...additionalData
    },
    'HTTP Response'
  )
}

export const logError = (error: Error, context?: Record<string, any>) => {
  logger.error(
    {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      },
      ...context
    },
    'Error occurred'
  )
}

export const logAuth = (action: string, userId?: string, additionalData?: Record<string, any>) => {
  authLogger.info(
    {
      action,
      userId,
      timestamp: new Date().toISOString(),
      ...additionalData
    },
    `Auth: ${action}`
  )
}

export const logAudit = (
  action: string,
  resource: string,
  userId?: string,
  additionalData?: Record<string, any>
) => {
  auditLogger.info(
    {
      action,
      resource,
      userId,
      timestamp: new Date().toISOString(),
      ...additionalData
    },
    `Audit: ${action} on ${resource}`
  )
}

export const logDatabase = (
  operation: string,
  table?: string,
  additionalData?: Record<string, any>
) => {
  dbLogger.debug(
    {
      operation,
      table,
      timestamp: new Date().toISOString(),
      ...additionalData
    },
    `DB: ${operation}${table ? ` on ${table}` : ''}`
  )
}

export const logEmail = (
  action: string,
  recipient: string,
  subject?: string,
  additionalData?: Record<string, any>
) => {
  emailLogger.info(
    {
      action,
      recipient,
      subject,
      timestamp: new Date().toISOString(),
      ...additionalData
    },
    `Email: ${action} to ${recipient}`
  )
}

// Performance logging
export const createPerformanceLogger = (operation: string) => {
  const start = process.hrtime.bigint()

  return {
    end: (additionalData?: Record<string, any>) => {
      const end = process.hrtime.bigint()
      const duration = Number(end - start) / 1000000 // Convert to milliseconds

      logger.debug(
        {
          operation,
          duration: `${duration.toFixed(2)}ms`,
          ...additionalData
        },
        `Performance: ${operation} completed in ${duration.toFixed(2)}ms`
      )

      return duration
    }
  }
}

// Health check logging
export const logHealth = (status: 'healthy' | 'unhealthy', checks: Record<string, boolean>) => {
  logger.info(
    {
      status,
      checks,
      timestamp: new Date().toISOString()
    },
    `Health check: ${status}`
  )
}

// Security event logging
export const logSecurity = (
  event: string,
  level: 'low' | 'medium' | 'high' | 'critical',
  details: Record<string, any>
) => {
  logger.warn(
    {
      securityEvent: event,
      level,
      timestamp: new Date().toISOString(),
      ...details
    },
    `Security: ${event} [${level.toUpperCase()}]`
  )
}

export default logger

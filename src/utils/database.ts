import { Prisma, PrismaClient } from '@prisma/client'
import { config } from '@/config/config.js'
import { dbLogger, logger } from './logger.js'

// Create Prisma client with enhanced configuration
export const prisma = new PrismaClient({
  log: config.isDevelopment
    ? [
        { emit: 'event', level: 'query' },
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'info' },
        { emit: 'event', level: 'warn' }
      ]
    : [
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'warn' }
      ],
  datasources: {
    db: {
      url: config.database.url
    }
  }
})

// Enhanced logging for Prisma events
prisma.$on('query', e => {
  dbLogger.debug(
    {
      query: e.query,
      params: e.params,
      duration: `${e.duration}ms`,
      target: e.target
    },
    'Database query executed'
  )
})

prisma.$on('error', e => {
  dbLogger.error(
    {
      target: e.target,
      timestamp: e.timestamp
    },
    'Database error occurred'
  )
})

prisma.$on('info', e => {
  dbLogger.info(
    {
      message: e.message,
      target: e.target,
      timestamp: e.timestamp
    },
    'Database info'
  )
})

prisma.$on('warn', e => {
  dbLogger.warn(
    {
      message: e.message,
      target: e.target,
      timestamp: e.timestamp
    },
    'Database warning'
  )
})

// Database connection health check
export async function checkDatabaseConnection(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`
    return true
  } catch (error) {
    logger.error(error, 'Database connection check failed')
    return false
  }
}

// Database utilities and helpers
export const db = {
  // Health check
  isHealthy: checkDatabaseConnection,

  // Connection info
  connect: async () => {
    try {
      await prisma.$connect()
      logger.info('✅ Database connected successfully')
    } catch (error) {
      logger.error(error, '❌ Failed to connect to database')
      throw error
    }
  },

  disconnect: async () => {
    try {
      await prisma.$disconnect()
      logger.info('Database disconnected')
    } catch (error) {
      logger.error(error, 'Error disconnecting from database')
    }
  },

  // Transaction wrapper with logging
  transaction: async <T>(
    callback: (
      tx: Omit<
        PrismaClient,
        '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
      >
    ) => Promise<T>,
    options?: {
      maxWait?: number
      timeout?: number
      isolationLevel?: Prisma.TransactionIsolationLevel
    }
  ): Promise<T> => {
    const start = Date.now()
    try {
      const result = await prisma.$transaction(tx => callback(tx), options)
      const duration = Date.now() - start
      dbLogger.debug({ duration: `${duration}ms` }, 'Transaction completed successfully')
      return result
    } catch (error) {
      const duration = Date.now() - start
      dbLogger.error({ error, duration: `${duration}ms` }, 'Transaction failed')
      throw error
    }
  },

  // Pagination helper
  paginate: <T>(data: T[], page: number, limit: number, total: number) => ({
    data,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNext: page < Math.ceil(total / limit),
      hasPrev: page > 1
    }
  }),

  // Common queries with caching
  findUserByEmail: async (email: string) => {
    return prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        roles: {
          include: {
            role: true
          }
        }
      }
    })
  },

  findUserById: async (id: string) => {
    return prisma.user.findUnique({
      where: { id },
      include: {
        roles: {
          include: {
            role: true
          }
        }
      }
    })
  },

  // User session management
  createUserSession: async (data: {
    userId: string
    refreshToken: string
    fingerprint?: string
    ipAddress?: string
    userAgent?: string
    deviceType?: string
    deviceName?: string
    expiresAt: Date
  }) => {
    return prisma.userSession.create({
      data
    })
  },

  findActiveSession: async (refreshToken: string) => {
    return prisma.userSession.findFirst({
      where: {
        refreshToken,
        isActive: true,
        expiresAt: {
          gt: new Date()
        }
      },
      include: {
        user: {
          include: {
            roles: {
              include: {
                role: true
              }
            }
          }
        }
      }
    })
  },

  // Audit logging
  createAuditLog: async (data: {
    userId?: string
    action: string
    resource: string
    resourceId?: string
    method?: string
    endpoint?: string
    ipAddress: string
    userAgent?: string
    oldData?: any
    newData?: any
    success: boolean
    errorMessage?: string
    metadata?: Record<string, any>
  }) => {
    if (!config.features.auditLogs) return null

    return prisma.auditLog.create({
      data: {
        ...data,
        oldData: data.oldData ? JSON.stringify(data.oldData) : undefined,
        newData: data.newData ? JSON.stringify(data.newData) : undefined
      }
    })
  },

  // Role and permission helpers
  getUserPermissions: async (userId: string): Promise<string[]> => {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        roles: {
          include: {
            role: true
          }
        }
      }
    })

    if (!user) return []

    const permissions = new Set<string>()

    for (const userRole of user.roles) {
      const rolePermissions = userRole.role.permissions as string[]
      rolePermissions.forEach(permission => permissions.add(permission))
    }

    return Array.from(permissions)
  },

  hasPermission: async (userId: string, permission: string): Promise<boolean> => {
    const permissions = await db.getUserPermissions(userId)
    return permissions.includes(permission)
  },

  hasRole: async (userId: string, roleName: string): Promise<boolean> => {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        roles: {
          include: {
            role: true
          }
        }
      }
    })

    if (!user) return false

    return user.roles.some(userRole => userRole.role.name === roleName)
  },

  // Token blacklist management
  blacklistToken: async (jti: string, userId?: string, reason?: string, expiresAt?: Date) => {
    return prisma.revokedToken.create({
      data: {
        jti,
        userId,
        reason,
        expiresAt: expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000) // 24h default
      }
    })
  },

  isTokenRevoked: async (jti: string): Promise<boolean> => {
    const revokedToken = await prisma.revokedToken.findUnique({
      where: { jti }
    })

    return !!revokedToken && revokedToken.expiresAt > new Date()
  },

  // Cleanup operations
  cleanupExpiredSessions: async () => {
    const result = await prisma.userSession.deleteMany({
      where: {
        OR: [{ expiresAt: { lt: new Date() } }, { isActive: false }]
      }
    })

    if (result.count > 0) {
      dbLogger.info({ deletedSessions: result.count }, 'Cleaned up expired sessions')
    }

    return result.count
  },

  cleanupExpiredTokens: async () => {
    const result = await prisma.revokedToken.deleteMany({
      where: {
        expiresAt: { lt: new Date() }
      }
    })

    if (result.count > 0) {
      dbLogger.info({ deletedTokens: result.count }, 'Cleaned up expired revoked tokens')
    }

    return result.count
  },

  // Settings management
  getSetting: async <T>(key: string, defaultValue?: T): Promise<T | null> => {
    const setting = await prisma.setting.findUnique({
      where: { key }
    })

    if (!setting) return defaultValue || null

    return setting.value as T
  },

  setSetting: async (key: string, value: any, type: string = 'json') => {
    return prisma.setting.upsert({
      where: { key },
      update: { value, type },
      create: { key, value, type }
    })
  }
}

export default prisma

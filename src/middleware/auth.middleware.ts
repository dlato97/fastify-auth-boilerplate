import type { FastifyReply, FastifyRequest } from 'fastify'
import { JWTPayload, jwtVerify } from 'jose'

import { config } from '@/config/config'
import { db, prisma } from '@/utils/database'
import { redis } from '@/utils/redis.js'
import { authLogger, logSecurity } from '@/utils/logger'
import { PreHandlerHook } from '@/types/fastify'

// JWT verification utility
async function verifyJWT(token: string): Promise<JWTPayload> {
  try {
    const secret = new TextEncoder().encode(config.jwt.accessSecret)
    const { payload } = await jwtVerify(token, secret)
    return payload
  } catch {
    throw new Error('Invalid token')
  }
}

// Main authentication middleware
export async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      })
    }

    const token = authHeader.substring(7)
    const payload = await verifyJWT(token)

    // Check if token is blacklisted
    /*  if (payload.jti && await redis.isTokenBlacklisted(payload.jti)) {
            logSecurity('blacklisted_token_used', 'medium', {
                jti: payload.jti,
                userId: payload.sub,
                ip: request.ip
            })

            return reply.code(401).send({
                error: 'Unauthorized',
                message: 'Token has been revoked'
            })
        }*/

    if (!payload.sub) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Invalid token payload'
      })
    }

    // Get user with roles
    const user = await db.findUserById(payload.sub)

    if (!user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'User not found'
      })
    }

    // Check if user is active
    if (!user.isActive) {
      logSecurity('inactive_user_access_attempt', 'medium', {
        userId: user.id,
        email: user.email,
        ip: request.ip
      })

      return reply.code(403).send({
        error: 'Forbidden',
        message: 'Account is deactivated'
      })
    }

    // Get user permissions
    const permissions = await db.getUserPermissions(user.id)

    // Attach user and permissions to request
    request.user = user
    request.permissions = permissions

    // Log successful authentication
    authLogger.debug(
      {
        userId: user.id,
        email: user.email,
        permissions: permissions.length,
        ip: request.ip
      },
      'User authenticated successfully'
    )
  } catch (error) {
    authLogger.error(error, 'Authentication failed')

    return reply.code(401).send({
      error: 'Unauthorized',
      message: 'Invalid or expired token'
    })
  }
}

// Optional authentication (doesn't fail if no token)
export async function optionalAuthenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return // Continue without authentication
    }

    await authenticate(request, reply)
  } catch {
    // Silently continue without authentication
    return
  }
}

// Role-based access control middleware factory
export function requireRoles(roles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    const userRoles = request.user.roles.map(ur => ur.role.name)
    const hasRequiredRole = roles.some(role => userRoles.includes(role))

    if (!hasRequiredRole) {
      logSecurity('insufficient_role_access', 'medium', {
        userId: request.user.id,
        requiredRoles: roles,
        userRoles,
        endpoint: request.routeOptions.schema,
        ip: request.ip
      })

      return reply.code(403).send({
        error: 'Forbidden',
        message: `Requires one of the following roles: ${roles.join(', ')}`
      })
    }
  }
}

// Permission-based access control middleware factory
export function requirePermissions(permissions: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    if (!request.permissions) {
      request.permissions = await db.getUserPermissions(request.user.id)
    }

    const hasAllPermissions = permissions.every(permission =>
      request.permissions!.includes(permission)
    )

    if (!hasAllPermissions) {
      const missingPermissions = permissions.filter(
        permission => !request.permissions!.includes(permission)
      )

      logSecurity('insufficient_permissions_access', 'medium', {
        userId: request.user.id,
        requiredPermissions: permissions,
        missingPermissions,
        userPermissions: request.permissions,
        endpoint: request.routeOptions.schema,
        ip: request.ip
      })

      return reply.code(403).send({
        error: 'Forbidden',
        message: `Missing required permissions: ${missingPermissions.join(', ')}`
      })
    }
  }
}

// Self or admin access middleware
export function requireSelfOrAdmin(userIdParam: string = 'id') {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    const targetUserId = (request.params as any)[userIdParam]
    const isAdmin = await db.hasRole(request.user.id, 'admin')
    const isSelf = request.user.id === targetUserId

    if (!isSelf && !isAdmin) {
      logSecurity('unauthorized_user_access', 'medium', {
        userId: request.user.id,
        targetUserId,
        endpoint: request.routeOptions.schema,
        ip: request.ip
      })

      return reply.code(403).send({
        error: 'Forbidden',
        message: 'Can only access your own resources or requires admin role'
      })
    }
  }
}

// Rate limiting based on user
export function requireUserRateLimit(maxRequests: number = 100, windowMs: number = 60000) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    const key = `user_rate_limit:${request.user.id}:${request.routeOptions.schema}`
    const result = await redis.incrementRateLimit(key, Math.floor(windowMs / 1000), maxRequests)

    if (result.count > maxRequests) {
      logSecurity('user_rate_limit_exceeded', 'low', {
        userId: request.user.id,
        endpoint: request.routeOptions.schema,
        count: result.count,
        limit: maxRequests,
        ip: request.ip
      })

      return reply.code(429).send({
        error: 'Too Many Requests',
        message: 'User rate limit exceeded',
        retryAfter: result.resetTime ? Math.floor((result.resetTime - Date.now()) / 1000) : 60
      })
    }

    // Add rate limit headers
    reply.headers({
      'X-RateLimit-Limit': maxRequests.toString(),
      'X-RateLimit-Remaining': result.remaining.toString(),
      'X-RateLimit-Reset': result.resetTime?.toString() || ''
    })
  }
}

// Email verification middleware
export function requireEmailVerified() {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    if (!request.user.isVerified) {
      return reply.code(403).send({
        error: 'Forbidden',
        message: 'Email verification required'
      })
    }
  }
}

// Two-factor authentication middleware
export function require2FA() {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    // Check if 2FA is enabled for the user
    if (request.user.twoFactorEnabled) {
      // Check if current session has been verified with 2FA
      const sessionKey = `2fa_verified:${request.user.id}`
      const isVerified = await redis.get(sessionKey)

      if (!isVerified) {
        return reply.code(403).send({
          error: 'Forbidden',
          message: 'Two-factor authentication required'
        })
      }
    }
  }
}

// Middleware to check if user owns resource
export function requireOwnership(resourceType: string, resourceIdParam: string = 'id') {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.user) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Authentication required'
      })
    }

    const resourceId = (request.params as any)[resourceIdParam]
    const isAdmin = await db.hasRole(request.user.id, 'admin')

    if (isAdmin) return // Admins can access any resource

    // Check ownership based on resource type
    let isOwner = false

    switch (resourceType) {
      case 'user':
        isOwner = request.user.id === resourceId
        break
      case 'session': {
        const session = await prisma.userSession.findUnique({
          where: { id: resourceId }
        })
        isOwner = session?.userId === request.user.id
        break
      }
      // Add more resource types as needed
      default:
        // Generic check - assume resource has userId field
        try {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-call
          const resource = await (prisma as any)[resourceType].findUnique({
            where: { id: resourceId },
            select: { userId: true }
          })
          isOwner = resource?.userId === request.user.id
        } catch (error) {
          authLogger.error(error, `Failed to check ownership for resource type: ${resourceType}`)
        }
    }

    if (!isOwner) {
      logSecurity('unauthorized_resource_access', 'medium', {
        userId: request.user.id,
        resourceType,
        resourceId,
        endpoint: request.routeOptions.schema,
        ip: request.ip
      })

      return reply.code(403).send({
        error: 'Forbidden',
        message: 'You do not own this resource'
      })
    }
  }
}

// Composite middleware helpers
export const authMiddleware = {
  // Basic authentication
  required: authenticate,
  optional: optionalAuthenticate,

  // Role-based
  admin: requireRoles(['admin']),
  moderator: requireRoles(['admin', 'moderator']),
  user: requireRoles(['admin', 'moderator', 'user']),

  // Permission-based
  readUsers: requirePermissions(['users:read']),
  writeUsers: requirePermissions(['users:write']),
  deleteUsers: requirePermissions(['users:delete']),
  manageUsers: requirePermissions(['users:manage']),
  systemAdmin: requirePermissions(['system:admin']),

  // Combined middleware
  authenticatedUser: [authenticate, requireEmailVerified()],
  authenticatedAdmin: [authenticate, requireRoles(['admin'])],
  authenticatedModerator: [authenticate, requireRoles(['admin', 'moderator'])],

  // Self or admin access
  selfOrAdmin: (userIdParam?: string) => [authenticate, requireSelfOrAdmin(userIdParam)],

  // With 2FA requirement
  with2FA: [authenticate, require2FA()],
  adminWith2FA: [authenticate, requireRoles(['admin']), require2FA()],

  // Resource ownership
  ownsResource: (resourceType: string, resourceIdParam?: string) => [
    authenticate,
    requireOwnership(resourceType, resourceIdParam)
  ]
}

// Hook factories for easier usage
export function createAuthHook(middleware: PreHandlerHook[]) {
  return {
    preHandler: middleware
  }
}

// Utility functions
export function extractTokenFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith('Bearer ')) {
    return null
  }
  return authHeader.substring(7)
}

export function getUserContext(request: FastifyRequest) {
  return {
    user: request.user,
    permissions: request.permissions,
    isAuthenticated: !!request.user,
    isAdmin: request.user?.roles.some(ur => ur.role.name === 'admin') || false,
    isModerator:
      request.user?.roles.some(ur => ['admin', 'moderator'].includes(ur.role.name)) || false
  }
}

import { authRoutes } from '@/routes/auth.routes.js'
import { userRoutes } from '@/routes/user.routes.js'
import { roleRoutes } from '@/routes/role.routes.js'
//import { adminRoutes } from '@/routes/admin.routes.js'
import { AppServer } from '@/types/server'
import { db } from '@/utils/database'

export async function registerRoutes(server: AppServer) {
  // Health check endpoint
  server.get('/health', async () => {
    const dbHealth = await db.isHealthy()
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      database: dbHealth
    }
  })

  // api/v1 routes -  Register all route modules with API version prefix
  await server.register(
    async function (server) {
      // Authentication routes - Public and protected auth endpoints
      await server.register(authRoutes, {
        prefix: '/auth',
        logLevel: 'info'
      })

      // User management routes - CRUD operations for users
      await server.register(userRoutes, {
        prefix: '/users',
        logLevel: 'info'
      })

      // Role management routes - RBAC system management
      await server.register(roleRoutes, {
        prefix: '/roles',
        logLevel: 'info'
      })

      // Add a general API info endpoint
      server.get(
        '/',
        {
          schema: {
            description: 'API Information',
            tags: ['General'],
            response: {
              200: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  version: { type: 'string' },
                  description: { type: 'string' },
                  endpoints: {
                    type: 'object',
                    properties: {
                      auth: { type: 'string' },
                      users: { type: 'string' },
                      roles: { type: 'string' },
                      admin: { type: 'string' },
                      documentation: { type: 'string' },
                      health: { type: 'string' }
                    }
                  },
                  features: {
                    type: 'array',
                    items: { type: 'string' }
                  }
                }
              }
            }
          }
        },
        async (request, reply) => {
          return reply.send({
            name: 'Fastify Auth API',
            version: '1.0.0',
            description: 'Modern authentication API with RBAC and comprehensive user management',
            endpoints: {
              auth: '/api/v1/auth',
              users: '/api/v1/users',
              roles: '/api/v1/roles',
              admin: '/api/v1/admin',
              documentation: '/documentation',
              health: '/health'
            },
            features: [
              'JWT Authentication with Refresh Tokens',
              'Two-Factor Authentication (TOTP)',
              'Role-Based Access Control (RBAC)',
              'Email Verification',
              'Password Reset',
              'Session Management',
              'Audit Logging',
              'Rate Limiting',
              'Real-time Security Monitoring',
              'Comprehensive Admin Dashboard'
            ]
          })
        }
      )
    },
    { prefix: '/api/v1' }
  )

  // Global error handler for API routes
  server.setErrorHandler(async (error, request, reply) => {
    request.log.error(error, 'API Error occurred')

    // Handle validation errors
    if (error.validation) {
      return reply.code(400).send({
        error: 'Validation Error',
        message: 'Request validation failed',
        details: error.validation,
        statusCode: 400,
        timestamp: new Date().toISOString(),
        requestId: request.id
      })
    }

    // Handle authentication errors
    if (error.statusCode === 401) {
      return reply.code(401).send({
        error: 'Unauthorized',
        message: error.message || 'Authentication required',
        statusCode: 401,
        timestamp: new Date().toISOString(),
        requestId: request.id
      })
    }

    // Handle authorization errors
    if (error.statusCode === 403) {
      return reply.code(403).send({
        error: 'Forbidden',
        message: error.message || 'Insufficient permissions',
        statusCode: 403,
        timestamp: new Date().toISOString(),
        requestId: request.id
      })
    }

    // Handle not found errors
    if (error.statusCode === 404) {
      return reply.code(404).send({
        error: 'Not Found',
        message: error.message || 'Resource not found',
        statusCode: 404,
        timestamp: new Date().toISOString(),
        requestId: request.id
      })
    }

    // Handle rate limiting errors
    if (error.statusCode === 429) {
      const retryAfter = 'retryAfter' in error ? error.retryAfter : 60
      return reply.code(429).send({
        error: 'Too Many Requests',
        message: error.message || 'Rate limit exceeded',
        statusCode: 429,
        timestamp: new Date().toISOString(),
        requestId: request.id,
        retryAfter: retryAfter
      })
    }

    // Handle other client errors (4xx)
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: error.name || 'Bad Request',
        message: error.message,
        statusCode: error.statusCode,
        timestamp: new Date().toISOString(),
        requestId: request.id
      })
    }

    // Handle server errors (5xx)
    const statusCode = error?.statusCode && error.statusCode >= 500 ? error.statusCode : 500

    return reply.code(statusCode).send({
      error: 'Internal Server Error',
      message:
        process.env.NODE_ENV === 'production' ? 'An unexpected error occurred' : error.message,
      statusCode,
      timestamp: new Date().toISOString(),
      requestId: request.id,
      ...(process.env.NODE_ENV !== 'production' && {
        stack: error.stack
      })
    })
  })

  // 404 handler for API routes
  server.setNotFoundHandler(async (request, reply) => {
    return reply.code(404).send({
      error: 'Not Found',
      message: `API endpoint ${request.method}:${request.url} not found`,
      statusCode: 404,
      timestamp: new Date().toISOString(),
      requestId: request.id,
      suggestion: 'Check the API documentation at /documentation'
    })
  })
}

// Route summary for documentation
export const routeSummary = {
  '/api/v1/auth': {
    description: 'Authentication and user profile management',
    endpoints: [
      'POST /register - Register new user',
      'POST /login - User login',
      'POST /verify-2fa - Complete 2FA login',
      'POST /refresh - Refresh access token',
      'POST /logout - User logout',
      'GET /me - Get user profile',
      'PUT /profile - Update user profile',
      'POST /change-password - Change password',
      'POST /forgot-password - Request password reset',
      'POST /reset-password - Reset password',
      'POST /verify-email - Verify email address',
      'GET /sessions - Get user sessions',
      'DELETE /sessions/:id - Terminate session',
      'POST /2fa/setup - Setup 2FA',
      'POST /2fa/enable - Enable 2FA',
      'POST /2fa/disable - Disable 2FA'
    ]
  },
  '/api/v1/users': {
    description: 'User management (Admin/Moderator access required)',
    endpoints: [
      'GET / - List users with pagination and filtering',
      'GET /:id - Get user details',
      'POST / - Create new user',
      'PUT /:id - Update user',
      'DELETE /:id - Delete user',
      'POST /:id/roles - Assign roles to user',
      'DELETE /:id/roles - Remove roles from user',
      'GET /:id/sessions - Get user sessions',
      'DELETE /:id/sessions - Terminate user sessions',
      'PATCH /:id/status - Activate/deactivate user',
      'POST /:id/force-password-reset - Force password reset'
    ]
  },
  '/api/v1/roles': {
    description: 'Role and permission management (Admin access required)',
    endpoints: [
      'GET / - List roles with pagination',
      'GET /:id - Get role details',
      'POST / - Create new role',
      'PUT /:id - Update role',
      'DELETE /:id - Delete role',
      'GET /:id/users - Get users with specific role',
      'GET /permissions/available - List available permissions',
      'POST /:id/duplicate - Duplicate existing role',
      'GET /hierarchy - Get role hierarchy tree'
    ]
  },
  '/api/v1/admin': {
    description: 'System administration (Super Admin access required)',
    endpoints: [
      'GET /dashboard - System dashboard and statistics',
      'GET /audit-logs - Audit logs with filtering',
      'GET /audit-logs/export - Export audit logs',
      'GET /settings - System settings',
      'PUT /settings/:key - Update system setting',
      'GET /sessions - All active sessions',
      'DELETE /sessions/:id - Terminate any session',
      'GET /security/events - Security events and alerts',
      'GET /health - Detailed system health',
      'POST /backup - Create system backup',
      'GET /backups - List available backups',
      'POST /maintenance - Toggle maintenance mode',
      'DELETE /cache - Clear system cache',
      'GET /cache/stats - Cache statistics',
      'POST /users/bulk-action - Bulk user operations',
      'GET /rate-limits - Rate limit status',
      'DELETE /rate-limits/:id - Reset rate limits',
      'GET /analytics/usage - Usage analytics',
      'POST /test-email - Send test emails',
      'GET /logs - System logs',
      'POST /database/cleanup - Database cleanup',
      'POST /import/users - Import users from CSV',
      'GET /export/users - Export users to CSV'
    ]
  }
}

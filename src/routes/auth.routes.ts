import type { FastifyInstance } from 'fastify'
import { authController } from '@/controllers/auth.controller.js'
import { authMiddleware } from '@/middleware/auth.middleware.js'

export async function authRoutes(server: FastifyInstance) {
  // Public authentication endpoints
  server.post(
    '/register',
    {
      schema: {
        description: 'Register a new user account',
        tags: ['Authentication'],
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 8 },
            firstName: { type: 'string' },
            lastName: { type: 'string' },
            username: { type: 'string', minLength: 3 }
          }
        },
        response: {
          201: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  email: { type: 'string' },
                  username: { type: 'string' },
                  firstName: { type: 'string' },
                  lastName: { type: 'string' },
                  isActive: { type: 'boolean' },
                  isVerified: { type: 'boolean' },
                  createdAt: { type: 'string' }
                }
              },
              tokens: {
                type: 'object',
                properties: {
                  accessToken: { type: 'string' },
                  expiresIn: { type: 'number' }
                }
              }
            }
          }
        }
      }
    },
    authController.register.bind(authController)
  )

  server.post(
    '/login',
    {
      schema: {
        description: 'Authenticate user and return tokens',
        tags: ['Authentication'],
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string' },
            rememberMe: { type: 'boolean' },
            deviceFingerprint: { type: 'string' }
          }
        },
        response: {
          200: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              user: {},
              tokens: {},
              requiresTwoFactor: { type: 'boolean' }
            }
          }
        }
      }
    },
    authController.login.bind(authController)
  )

  server.post(
    '/refresh',
    {
      schema: {
        description: 'Refresh access token using refresh token',
        tags: ['Authentication'],
        body: {
          type: 'object',
          properties: {
            refreshToken: { type: 'string' }
          }
        }
      }
    },
    authController.refreshToken.bind(authController)
  )

  server.post(
    '/forgot-password',
    {
      schema: {
        description: 'Request password reset email',
        tags: ['Authentication'],
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' }
          }
        }
      }
    },
    authController.forgotPassword.bind(authController)
  )

  server.post(
    '/reset-password',
    {
      schema: {
        description: 'Reset password using reset token',
        tags: ['Authentication'],
        body: {
          type: 'object',
          required: ['token', 'password', 'confirmPassword'],
          properties: {
            token: { type: 'string' },
            password: { type: 'string', minLength: 8 },
            confirmPassword: { type: 'string', minLength: 8 }
          }
        }
      }
    },
    authController.resetPassword.bind(authController)
  )

  server.post(
    '/verify-email',
    {
      schema: {
        description: 'Verify user email address',
        tags: ['Authentication'],
        body: {
          type: 'object',
          required: ['token'],
          properties: {
            token: { type: 'string' }
          }
        }
      }
    },
    authController.verifyEmail.bind(authController)
  )

  // Protected authentication endpoints
  server.post(
    '/logout',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Logout user and invalidate tokens',
        tags: ['Authentication'],
        security: [{ bearerAuth: [] }]
      }
    },
    authController.logout.bind(authController)
  )

  server.get(
    '/me',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Get current user profile',
        tags: ['Authentication'],
        security: [{ bearerAuth: [] }],
        response: {
          200: {
            type: 'object',
            properties: {
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  email: { type: 'string' },
                  username: { type: 'string' },
                  firstName: { type: 'string' },
                  lastName: { type: 'string' },
                  avatar: { type: 'string' },
                  isActive: { type: 'boolean' },
                  isVerified: { type: 'boolean' },
                  twoFactorEnabled: { type: 'boolean' },
                  lastLoginAt: { type: 'string' },
                  createdAt: { type: 'string' },
                  roles: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        role: {
                          type: 'object',
                          properties: {
                            id: { type: 'string' },
                            name: { type: 'string' },
                            displayName: { type: 'string' },
                            permissions: {
                              type: 'array',
                              items: { type: 'string' }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    authController.getProfile.bind(authController)
  )

  server.put(
    '/profile',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Update user profile',
        tags: ['Authentication'],
        security: [{ bearerAuth: [] }],
        body: {
          type: 'object',
          properties: {
            firstName: { type: 'string' },
            lastName: { type: 'string' },
            username: { type: 'string', minLength: 3 },
            avatar: { type: 'string', format: 'uri' },
            preferences: { type: 'object' },
            metadata: { type: 'object' }
          }
        }
      }
    },
    authController.updateProfile.bind(authController)
  )

  server.post(
    '/change-password',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Change user password',
        tags: ['Authentication'],
        security: [{ bearerAuth: [] }],
        body: {
          type: 'object',
          required: ['currentPassword', 'newPassword', 'confirmPassword'],
          properties: {
            currentPassword: { type: 'string' },
            newPassword: { type: 'string', minLength: 8 },
            confirmPassword: { type: 'string', minLength: 8 }
          }
        }
      }
    },
    authController.changePassword.bind(authController)
  )

  // Session management
  server.get(
    '/sessions',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Get user active sessions',
        tags: ['Sessions'],
        security: [{ bearerAuth: [] }],
        response: {
          200: {
            type: 'object',
            properties: {
              sessions: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    fingerprint: { type: 'string' },
                    ipAddress: { type: 'string' },
                    userAgent: { type: 'string' },
                    deviceType: { type: 'string' },
                    deviceName: { type: 'string' },
                    lastUsedAt: { type: 'string' },
                    createdAt: { type: 'string' },
                    expiresAt: { type: 'string' }
                  }
                }
              }
            }
          }
        }
      }
    },
    authController.getSessions.bind(authController)
  )

  server.delete(
    '/sessions/:sessionId',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Terminate specific session',
        tags: ['Sessions'],
        security: [{ bearerAuth: [] }],
        params: {
          type: 'object',
          required: ['sessionId'],
          properties: {
            sessionId: { type: 'string' }
          }
        }
      }
    },
    authController.terminateSession.bind(authController)
  )

  server.delete(
    '/sessions',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Terminate all sessions except current',
        tags: ['Sessions'],
        security: [{ bearerAuth: [] }]
      }
    },
    authController.terminateAllSessions.bind(authController)
  )
}

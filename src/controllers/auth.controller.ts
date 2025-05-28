import type { FastifyReply, FastifyRequest } from 'fastify'
import { authService } from '@/services/auth.service.js'
import { db, prisma } from '@/utils/database.js'
import { authLogger } from '@/utils/logger.js'
import {
  changePasswordSchema,
  forgotPasswordSchema,
  loginSchema,
  refreshTokenSchema,
  registerSchema,
  resetPasswordSchema,
  updateProfileSchema,
  verifyEmailSchema
} from '@/schemas/auth.schemas.js'

export class AuthController {
  // Register new user
  async register(request: FastifyRequest, reply: FastifyReply) {
    try {
      const data = registerSchema.parse(request.body)
      const ipAddress = request.ip

      const result = await authService.register(data, ipAddress)

      // Set refresh token as httpOnly cookie
      reply.setCookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      })

      return reply.code(201).send({
        message: 'User registered successfully',
        user: result.user,
        tokens: {
          accessToken: result.tokens.accessToken,
          expiresIn: result.tokens.expiresIn
        }
      })
    } catch (error: any) {
      authLogger.error(error, 'Registration failed')
      return reply.code(400).send({
        error: 'Registration Failed',
        message: error.message
      })
    }
  }

  // User login
  async login(request: FastifyRequest, reply: FastifyReply) {
    try {
      const data = loginSchema.parse(request.body)
      const ipAddress = request.ip
      const userAgent = request.headers['user-agent']

      const result = await authService.login(data, ipAddress, userAgent)

      // If 2FA is required, return partial response
      if (result.requiresTwoFactor) {
        // Store user ID temporarily for 2FA verification
        /*const tempToken = await redis.set(
          `2fa_pending:${result.user.id}`,
          JSON.stringify({ userId: result.user.id, email: result.user.email }),
          300 // 5 minutes
        )*/

        return reply.send({
          message: 'Two-factor authentication required',
          requiresTwoFactor: true,
          tempUserId: result.user.id
        })
      }

      // Set refresh token as httpOnly cookie
      reply.setCookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      })

      return reply.send({
        message: 'Login successful',
        user: result.user,
        tokens: {
          accessToken: result.tokens.accessToken,
          expiresIn: result.tokens.expiresIn
        }
      })
    } catch (error: any) {
      return reply.code(400).send({
        error: 'Login Failed',
        message: error.message
      })
    }
  }

  // Refresh access token
  async refreshToken(request: FastifyRequest, reply: FastifyReply) {
    try {
      const refreshToken =
        request.cookies.refreshToken || refreshTokenSchema.parse(request.body).refreshToken

      if (!refreshToken) {
        return reply.code(400).send({
          error: 'Missing Token',
          message: 'Refresh token is required'
        })
      }

      const tokens = await authService.refreshTokens(refreshToken, request.ip)

      // Update refresh token cookie
      reply.setCookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      })

      return reply.send({
        message: 'Token refreshed successfully',
        tokens: {
          accessToken: tokens.accessToken,
          expiresIn: tokens.expiresIn
        }
      })
    } catch (error: any) {
      return reply.code(401).send({
        error: 'Token Refresh Failed',
        message: error.message
      })
    }
  }

  // User logout
  async logout(request: FastifyRequest, reply: FastifyReply) {
    try {
      const refreshToken = request.cookies.refreshToken
      const userId = request.user?.id

      if (refreshToken && userId) {
        await authService.logout(refreshToken, userId, request.ip)
      }

      // Clear refresh token cookie
      reply.clearCookie('refreshToken')

      /*    // Clear 2FA verification if exists
            if (userId) {
                await redis.del(`2fa_verified:${userId}`)
            }*/

      return reply.send({
        message: 'Logged out successfully'
      })
    } catch (error: any) {
      return reply.code(400).send({
        error: 'Logout Failed',
        message: error.message
      })
    }
  }

  // Get current user profile
  async getProfile(request: FastifyRequest, reply: FastifyReply) {
    try {
      console.log(request.user)
      if (!request.user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        })
      }

      const user = await db.findUserById(request.user.id)
      if (!user) {
        return reply.code(404).send({
          error: 'User Not Found',
          message: 'User profile not found'
        })
      }

      return reply.send({
        user: {
          ...user,
          password: undefined,
          twoFactorSecret: undefined,
          verifyToken: undefined,
          passwordResetToken: undefined
        }
      })
    } catch (error: any) {
      return reply.code(500).send({
        error: 'Profile Fetch Failed',
        message: error.message
      })
    }
  }

  // Update user profile
  async updateProfile(request: FastifyRequest, reply: FastifyReply) {
    try {
      if (!request.user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        })
      }

      const data = updateProfileSchema.parse(request.body)

      // Check if username is already taken
      if (data.username) {
        const existingUser = await prisma.user.findFirst({
          where: {
            username: data.username,
            id: { not: request.user.id }
          }
        })

        if (existingUser) {
          return reply.code(400).send({
            error: 'Username Taken',
            message: 'Username is already taken'
          })
        }
      }

      const updatedUser = await prisma.user.update({
        where: { id: request.user.id },
        data,
        include: {
          roles: {
            include: {
              role: true
            }
          }
        }
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user.id,
        action: 'profile_updated',
        resource: 'user',
        resourceId: request.user.id,
        ipAddress: request.ip,
        newData: data,
        success: true
      })

      return reply.send({
        message: 'Profile updated successfully',
        user: {
          ...updatedUser,
          password: undefined,
          twoFactorSecret: undefined
        }
      })
    } catch (error: any) {
      return reply.code(400).send({
        error: 'Profile Update Failed',
        message: error.message
      })
    }
  }

  // Change password
  async changePassword(request: FastifyRequest, reply: FastifyReply) {
    try {
      if (!request.user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        })
      }

      const data = changePasswordSchema.parse(request.body)

      await authService.changePassword(request.user.id, data, request.ip)

      return reply.send({
        message: 'Password changed successfully'
      })
    } catch (error: any) {
      return reply.code(400).send({
        error: 'Password Change Failed',
        message: error.message
      })
    }
  }

  // Forgot password
  async forgotPassword(request: FastifyRequest, reply: FastifyReply) {
    try {
      const data = forgotPasswordSchema.parse(request.body)

      await authService.forgotPassword(data.email, request.ip)

      return reply.send({
        message: 'If an account with that email exists, a password reset link has been sent'
      })
    } catch {
      // Always return success to prevent email enumeration
      return reply.send({
        message: 'If an account with that email exists, a password reset link has been sent'
      })
    }
  }

  // Reset password
  async resetPassword(request: FastifyRequest, reply: FastifyReply) {
    try {
      const data = resetPasswordSchema.parse(request.body)

      await authService.resetPassword(data.token, data.password, request.ip)

      return reply.send({
        message: 'Password reset successfully'
      })
    } catch (error: any) {
      return reply.code(400).send({
        error: 'Password Reset Failed',
        message: error.message
      })
    }
  }

  // Verify email
  async verifyEmail(request: FastifyRequest, reply: FastifyReply) {
    try {
      const data = verifyEmailSchema.parse(request.body)

      await authService.verifyEmail(data.token, request.ip)

      return reply.send({
        message: 'Email verified successfully'
      })
    } catch (error: any) {
      return reply.code(400).send({
        error: 'Email Verification Failed',
        message: error.message
      })
    }
  }

  // Get user sessions
  async getSessions(request: FastifyRequest, reply: FastifyReply) {
    try {
      if (!request.user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        })
      }

      const sessions = await prisma.userSession.findMany({
        where: {
          userId: request.user.id,
          isActive: true,
          expiresAt: { gt: new Date() }
        },
        select: {
          id: true,
          fingerprint: true,
          ipAddress: true,
          userAgent: true,
          deviceType: true,
          deviceName: true,
          lastUsedAt: true,
          createdAt: true,
          expiresAt: true
        },
        orderBy: { lastUsedAt: 'desc' }
      })

      return reply.send({
        sessions
      })
    } catch (error: any) {
      return reply.code(500).send({
        error: 'Sessions Fetch Failed',
        message: error.message
      })
    }
  }

  // Terminate session
  async terminateSession(request: FastifyRequest, reply: FastifyReply) {
    try {
      if (!request.user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        })
      }

      const { sessionId } = request.params as { sessionId: string }

      // Check if session belongs to user
      const session = await prisma.userSession.findFirst({
        where: {
          id: sessionId,
          userId: request.user.id
        }
      })

      if (!session) {
        return reply.code(404).send({
          error: 'Session Not Found',
          message: 'Session not found or access denied'
        })
      }

      // Deactivate session
      await prisma.userSession.update({
        where: { id: sessionId },
        data: { isActive: false }
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user.id,
        action: 'session_terminated',
        resource: 'session',
        resourceId: sessionId,
        ipAddress: request.ip,
        success: true
      })

      return reply.send({
        message: 'Session terminated successfully'
      })
    } catch (error: any) {
      return reply.code(500).send({
        error: 'Session Termination Failed',
        message: error.message
      })
    }
  }

  // Terminate all sessions
  async terminateAllSessions(request: FastifyRequest, reply: FastifyReply) {
    try {
      if (!request.user) {
        return reply.code(401).send({
          error: 'Unauthorized',
          message: 'Authentication required'
        })
      }

      // Get current session to exclude it
      const currentRefreshToken = request.cookies.refreshToken

      const result = await prisma.userSession.updateMany({
        where: {
          userId: request.user.id,
          isActive: true,
          ...(currentRefreshToken && {
            refreshToken: { not: currentRefreshToken }
          })
        },
        data: { isActive: false }
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user.id,
        action: 'all_sessions_terminated',
        resource: 'user',
        resourceId: request.user.id,
        ipAddress: request.ip,
        metadata: { terminatedCount: result.count },
        success: true
      })

      return reply.send({
        message: `${result.count} sessions terminated successfully`
      })
    } catch (error: any) {
      return reply.code(500).send({
        error: 'Sessions Termination Failed',
        message: error.message
      })
    }
  }
}

export const authController = new AuthController()

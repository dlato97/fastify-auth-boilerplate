import { hash, verify } from '@node-rs/argon2'
import { SignJWT, jwtVerify } from 'jose'
import { nanoid } from 'nanoid'

import { config } from '@/config/config.js'
import { db, prisma } from '@/utils/database.js'
import { emailService } from './email.service.js'
import { authLogger, logSecurity } from '@/utils/logger.js'
import type { RegisterInput, LoginInput, ChangePasswordInput } from '@/schemas/auth.schemas.js'

export interface TokenPair {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

export interface AuthResult {
  user: any
  tokens: TokenPair
  requiresTwoFactor?: boolean
}

export class AuthService {
  // Password hashing
  async hashPassword(password: string): Promise<string> {
    try {
      return await hash(password, {
        memoryCost: 65536, // 64 MB
        timeCost: 3,
        parallelism: 4
      })
    } catch (error) {
      authLogger.error(error, 'Failed to hash password')
      throw new Error('Password hashing failed')
    }
  }

  async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
      return await verify(hashedPassword, password)
    } catch (error) {
      authLogger.error(error, 'Failed to verify password')
      return false
    }
  }

  // JWT token generation
  async generateAccessToken(userId: string, permissions: string[]): Promise<string> {
    const secret = new TextEncoder().encode(config.jwt.accessSecret)
    const jti = nanoid()

    return await new SignJWT({
      sub: userId,
      permissions,
      type: 'access'
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime(config.jwt.accessExpiresIn)
      .setIssuer(config.urls.app)
      .setAudience(config.urls.app)
      .sign(secret)
  }

  async generateRefreshToken(userId: string): Promise<string> {
    const secret = new TextEncoder().encode(config.jwt.refreshSecret)
    const jti = nanoid()

    return await new SignJWT({
      sub: userId,
      type: 'refresh'
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime(config.jwt.refreshExpiresIn)
      .setIssuer(config.urls.app)
      .setAudience(config.urls.app)
      .sign(secret)
  }

  async verifyRefreshToken(token: string): Promise<any> {
    try {
      const secret = new TextEncoder().encode(config.jwt.refreshSecret)
      const { payload } = await jwtVerify(token, secret)
      return payload
    } catch (error) {
      throw new Error('Invalid refresh token')
    }
  }

  // Token pair generation
  async generateTokenPair(userId: string): Promise<TokenPair> {
    const permissions = await db.getUserPermissions(userId)
    const accessToken = await this.generateAccessToken(userId, permissions)
    const refreshToken = await this.generateRefreshToken(userId)

    // Store refresh token in database
    await db.createUserSession({
      userId,
      refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    })

    return {
      accessToken,
      refreshToken,
      expiresIn: 15 * 60 // 15 minutes
    }
  }

  // User registration
  async register(data: RegisterInput, ipAddress: string): Promise<AuthResult> {
    try {
      // Check if user exists
      const existingUser = await db.findUserByEmail(data.email)
      if (existingUser) {
        throw new Error('User already exists with this email')
      }

      // Check username if provided
      if (data.username) {
        const existingUsername = await prisma.user.findUnique({
          where: { username: data.username }
        })
        if (existingUsername) {
          throw new Error('Username already taken')
        }
      }

      // Hash password
      const hashedPassword = await this.hashPassword(data.password)

      // Generate verification token
      const verifyToken = nanoid(32)

      // Create user
      const user = await prisma.user.create({
        data: {
          email: data.email.toLowerCase(),
          username: data.username,
          firstName: data.firstName,
          lastName: data.lastName,
          password: hashedPassword,
          verifyToken,
          isActive: true,
          isVerified: !config.features.emailVerification
        },
        include: {
          roles: {
            include: {
              role: true
            }
          }
        }
      })

      // Assign default user role
      const userRole = await prisma.role.findUnique({
        where: { name: 'user' }
      })

      if (userRole) {
        await prisma.userRole.create({
          data: {
            userId: user.id,
            roleId: userRole.id
          }
        })
      }

      // Send verification email if enabled
      if (config.features.emailVerification) {
        await emailService.sendVerificationEmail(user.email, verifyToken)
      }

      // Create audit log
      await db.createAuditLog({
        userId: user.id,
        action: 'user_register',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        success: true,
        newData: {
          email: user.email,
          username: user.username
        }
      })

      authLogger.info(
        {
          userId: user.id,
          email: user.email,
          ip: ipAddress
        },
        'User registered successfully'
      )

      // Generate tokens
      const tokens = await this.generateTokenPair(user.id)

      return {
        user: {
          ...user,
          password: undefined, // Remove password from response
          verifyToken: undefined
        },
        tokens
      }
    } catch (error) {
      authLogger.error(error, 'Registration failed')
      throw error
    }
  }

  // User login
  async login(data: LoginInput, ipAddress: string, userAgent?: string): Promise<AuthResult> {
    try {
      // Find user
      const user = await db.findUserByEmail(data.email)
      if (!user) {
        // Log failed attempt
        logSecurity('login_attempt_invalid_email', 'low', {
          email: data.email,
          ip: ipAddress
        })
        throw new Error('Invalid credentials')
      }

      // Check if user is active
      if (!user.isActive) {
        logSecurity('login_attempt_inactive_user', 'medium', {
          userId: user.id,
          email: user.email,
          ip: ipAddress
        })
        throw new Error('Account is deactivated')
      }

      // Verify password
      const isValidPassword = await this.verifyPassword(data.password, user.password)
      if (!isValidPassword) {
        logSecurity('login_attempt_invalid_password', 'medium', {
          userId: user.id,
          email: user.email,
          ip: ipAddress
        })
        throw new Error('Invalid credentials')
      }

      // Check if 2FA is required
      if (user.twoFactorEnabled) {
        // Return partial result indicating 2FA is required
        return {
          user: {
            id: user.id,
            email: user.email,
            twoFactorEnabled: true
          },
          tokens: {
            accessToken: '',
            refreshToken: '',
            expiresIn: 0
          },
          requiresTwoFactor: true
        }
      }

      // Update last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
      })

      // Generate tokens
      const tokens = await this.generateTokenPair(user.id)

      // Create audit log
      await db.createAuditLog({
        userId: user.id,
        action: 'user_login',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        userAgent,
        success: true
      })

      authLogger.info(
        {
          userId: user.id,
          email: user.email,
          ip: ipAddress
        },
        'User logged in successfully'
      )

      return {
        user: {
          ...user,
          password: undefined
        },
        tokens
      }
    } catch (error) {
      authLogger.error(error, 'Login failed')
      throw error
    }
  }

  // Refresh tokens
  async refreshTokens(refreshToken: string, ipAddress: string): Promise<TokenPair> {
    try {
      // Verify refresh token
      const payload = await this.verifyRefreshToken(refreshToken)

      // Find active session
      const session = await db.findActiveSession(refreshToken)
      if (!session) {
        throw new Error('Invalid or expired refresh token')
      }

      // Check if user is still active
      if (!session.user.isActive) {
        throw new Error('Account is deactivated')
      }

      // Generate new token pair
      const newTokens = await this.generateTokenPair(session.userId)

      // Revoke old refresh token
      await prisma.userSession.update({
        where: { id: session.id },
        data: { isActive: false }
      })

      // Update session last used
      await prisma.userSession.updateMany({
        where: { refreshToken: newTokens.refreshToken },
        data: { lastUsedAt: new Date() }
      })

      authLogger.info(
        {
          userId: session.userId,
          sessionId: session.id,
          ip: ipAddress
        },
        'Tokens refreshed successfully'
      )

      return newTokens
    } catch (error) {
      authLogger.error(error, 'Token refresh failed')
      throw error
    }
  }

  // Logout
  async logout(refreshToken: string, userId: string, ipAddress: string): Promise<void> {
    try {
      // Find and deactivate session
      await prisma.userSession.updateMany({
        where: {
          refreshToken,
          userId,
          isActive: true
        },
        data: { isActive: false }
      })

      // Create audit log
      await db.createAuditLog({
        userId,
        action: 'user_logout',
        resource: 'user',
        resourceId: userId,
        ipAddress,
        success: true
      })

      authLogger.info(
        {
          userId,
          ip: ipAddress
        },
        'User logged out successfully'
      )
    } catch (error) {
      authLogger.error(error, 'Logout failed')
      throw error
    }
  }

  // Change password
  async changePassword(
    userId: string,
    data: ChangePasswordInput,
    ipAddress: string
  ): Promise<void> {
    try {
      // Get current user
      const user = await prisma.user.findUnique({
        where: { id: userId }
      })

      if (!user) {
        throw new Error('User not found')
      }

      // Verify current password
      const isValidPassword = await this.verifyPassword(data.currentPassword, user.password)
      if (!isValidPassword) {
        logSecurity('password_change_invalid_current', 'medium', {
          userId,
          ip: ipAddress
        })
        throw new Error('Current password is incorrect')
      }

      // Hash new password
      const hashedPassword = await this.hashPassword(data.newPassword)

      // Update password
      await prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword }
      })

      // Revoke all existing sessions except current one
      await prisma.userSession.updateMany({
        where: {
          userId,
          isActive: true
        },
        data: { isActive: false }
      })

      // Create audit log
      await db.createAuditLog({
        userId,
        action: 'password_changed',
        resource: 'user',
        resourceId: userId,
        ipAddress,
        success: true
      })

      authLogger.info(
        {
          userId,
          ip: ipAddress
        },
        'Password changed successfully'
      )
    } catch (error) {
      authLogger.error(error, 'Password change failed')
      throw error
    }
  }

  // Forgot password
  async forgotPassword(email: string, ipAddress: string): Promise<void> {
    try {
      const user = await db.findUserByEmail(email)

      // Always return success to prevent email enumeration
      if (!user) {
        authLogger.info(
          {
            email,
            ip: ipAddress
          },
          'Password reset requested for non-existent email'
        )
        return
      }

      // Generate reset token
      const resetToken = nanoid(32)
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000) // 1 hour

      // Update user with reset token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordResetToken: resetToken,
          passwordResetExpires: resetExpires
        }
      })

      // Send reset email
      await emailService.sendPasswordResetEmail(user.email, resetToken)

      // Create audit log
      await db.createAuditLog({
        userId: user.id,
        action: 'password_reset_requested',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        success: true
      })

      authLogger.info(
        {
          userId: user.id,
          email: user.email,
          ip: ipAddress
        },
        'Password reset requested'
      )
    } catch (error) {
      authLogger.error(error, 'Password reset request failed')
      throw error
    }
  }

  // Reset password
  async resetPassword(token: string, newPassword: string, ipAddress: string): Promise<void> {
    try {
      // Find user by reset token
      const user = await prisma.user.findFirst({
        where: {
          passwordResetToken: token,
          passwordResetExpires: {
            gt: new Date()
          }
        }
      })

      if (!user) {
        throw new Error('Invalid or expired reset token')
      }

      // Hash new password
      const hashedPassword = await this.hashPassword(newPassword)

      // Update user
      await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          passwordResetToken: null,
          passwordResetExpires: null
        }
      })

      // Revoke all existing sessions
      await prisma.userSession.updateMany({
        where: { userId: user.id },
        data: { isActive: false }
      })

      // Create audit log
      await db.createAuditLog({
        userId: user.id,
        action: 'password_reset_completed',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        success: true
      })

      authLogger.info(
        {
          userId: user.id,
          ip: ipAddress
        },
        'Password reset completed'
      )
    } catch (error) {
      authLogger.error(error, 'Password reset failed')
      throw error
    }
  }

  // Email verification
  async verifyEmail(token: string, ipAddress: string): Promise<void> {
    try {
      const user = await prisma.user.findFirst({
        where: { verifyToken: token }
      })

      if (!user) {
        throw new Error('Invalid verification token')
      }

      if (user.isVerified) {
        throw new Error('Email already verified')
      }

      // Update user as verified
      await prisma.user.update({
        where: { id: user.id },
        data: {
          isVerified: true,
          verifyToken: null
        }
      })

      // Create audit log
      await db.createAuditLog({
        userId: user.id,
        action: 'email_verified',
        resource: 'user',
        resourceId: user.id,
        ipAddress,
        success: true
      })

      authLogger.info(
        {
          userId: user.id,
          email: user.email,
          ip: ipAddress
        },
        'Email verified successfully'
      )
    } catch (error) {
      authLogger.error(error, 'Email verification failed')
      throw error
    }
  }
}

export const authService = new AuthService()

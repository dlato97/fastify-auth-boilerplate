import { PrismaClient } from '@prisma/client'
import { hash } from '@node-rs/argon2'
import { nanoid } from 'nanoid'

const prisma = new PrismaClient()

async function hashPassword(password: string): Promise<string> {
    return await hash(password, {
        memoryCost: 65536, // 64 MB
        timeCost: 3,
        parallelism: 4
    })
}

async function seedRoles() {
    console.log('🔐 Seeding roles...')

    const roles = [
        {
            name: 'admin',
            displayName: 'Administrator',
            description: 'Full system access with all permissions',
            color: '#dc2626',
            permissions: [
                'system:admin',
                'users:read', 'users:write', 'users:delete', 'users:manage',
                'roles:read', 'roles:write', 'roles:delete', 'roles:manage',
                'audit:read', 'audit:export',
                'settings:read', 'settings:write',
                'sessions:manage',
                'backup:create', 'backup:restore'
            ],
            isSystem: true
        },
        {
            name: 'moderator',
            displayName: 'Moderator',
            description: 'Content moderation and user management',
            color: '#ea580c',
            permissions: [
                'users:read', 'users:write',
                'audit:read',
                'sessions:view'
            ],
            isSystem: true
        },
        {
            name: 'user',
            displayName: 'User',
            description: 'Standard user with basic permissions',
            color: '#16a34a',
            permissions: [
                'profile:read', 'profile:write',
                'sessions:view'
            ],
            isSystem: true
        },
        {
            name: 'guest',
            displayName: 'Guest',
            description: 'Limited access for unverified users',
            color: '#6b7280',
            permissions: [
                'profile:read'
            ],
            isSystem: true
        }
    ]

    for (const roleData of roles) {
        await prisma.role.upsert({
            where: { name: roleData.name },
            update: {
                displayName: roleData.displayName,
                description: roleData.description,
                permissions: roleData.permissions,
                color: roleData.color
            },
            create: {
                ...roleData,
                permissions: roleData.permissions
            }
        })
        console.log(`✅ Role '${roleData.name}' seeded`)
    }
}

async function seedUsers() {
    console.log('👥 Seeding users...')

    const users = [
        {
            email: 'admin@example.com',
            username: 'admin',
            firstName: 'Admin',
            lastName: 'User',
            password: 'Admin123!@#',
            isActive: true,
            isVerified: true,
            roles: ['admin']
        },
        {
            email: 'moderator@example.com',
            username: 'moderator',
            firstName: 'Moderator',
            lastName: 'User',
            password: 'Moderator123!',
            isActive: true,
            isVerified: true,
            roles: ['moderator']
        },
        {
            email: 'user@example.com',
            username: 'testuser',
            firstName: 'Test',
            lastName: 'User',
            password: 'User123!',
            isActive: true,
            isVerified: true,
            roles: ['user']
        },
        {
            email: 'john.doe@example.com',
            username: 'johndoe',
            firstName: 'John',
            lastName: 'Doe',
            password: 'JohnDoe123!',
            isActive: true,
            isVerified: false,
            roles: ['user']
        },
        {
            email: 'jane.smith@example.com',
            username: 'janesmith',
            firstName: 'Jane',
            lastName: 'Smith',
            password: 'JaneSmith123!',
            isActive: false,
            isVerified: false,
            roles: ['guest']
        }
    ]

    for (const userData of users) {
        const existingUser = await prisma.user.findUnique({
            where: { email: userData.email }
        })

        if (existingUser) {
            console.log(`⚠️  User '${userData.email}' already exists, skipping...`)
            continue
        }

        const hashedPassword = await hashPassword(userData.password)

        const user = await prisma.user.create({
            data: {
                email: userData.email,
                username: userData.username,
                firstName: userData.firstName,
                lastName: userData.lastName,
                password: hashedPassword,
                isActive: userData.isActive,
                isVerified: userData.isVerified,
                verifyToken: userData.isVerified ? null : nanoid(32),
                preferences: {
                    theme: 'light',
                    language: 'en',
                    notifications: {
                        email: true,
                        push: false,
                        security: true
                    }
                },
                metadata: {
                    source: 'seeder',
                    createdBy: 'system'
                }
            }
        })

        // Assign roles
        for (const roleName of userData.roles) {
            const role = await prisma.role.findUnique({
                where: { name: roleName }
            })

            if (role) {
                await prisma.userRole.create({
                    data: {
                        userId: user.id,
                        roleId: role.id,
                        assignedBy: 'system'
                    }
                })
            }
        }

        console.log(`✅ User '${userData.email}' seeded with roles: ${userData.roles.join(', ')}`)
    }
}

async function seedSettings() {
    console.log('⚙️  Seeding settings...')

    const settings = [
        // Application settings
        {
            key: 'app.name',
            value: 'Your Application',
            type: 'string',
            description: 'Application name',
            isPublic: true,
            isSystem: false
        },
        {
            key: 'app.version',
            value: '1.0.0',
            type: 'string',
            description: 'Application version',
            isPublic: true,
            isSystem: true
        },
        {
            key: 'app.description',
            value: 'A modern web application with authentication and authorization',
            type: 'string',
            description: 'Application description',
            isPublic: true,
            isSystem: false
        },

        // Authentication settings
        {
            key: 'auth.email_verification_required',
            value: true,
            type: 'boolean',
            description: 'Require email verification for new users',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'auth.password_min_length',
            value: 8,
            type: 'number',
            description: 'Minimum password length',
            isPublic: true,
            isSystem: false
        },
        {
            key: 'auth.max_login_attempts',
            value: 5,
            type: 'number',
            description: 'Maximum login attempts before lockout',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'auth.lockout_duration',
            value: 15,
            type: 'number',
            description: 'Account lockout duration in minutes',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'auth.session_timeout',
            value: 7,
            type: 'number',
            description: 'Session timeout in days',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'auth.jwt_access_expires',
            value: '15m',
            type: 'string',
            description: 'JWT access token expiration',
            isPublic: false,
            isSystem: true
        },
        {
            key: 'auth.jwt_refresh_expires',
            value: '7d',
            type: 'string',
            description: 'JWT refresh token expiration',
            isPublic: false,
            isSystem: true
        },

        // Security settings
        {
            key: 'security.rate_limit_requests',
            value: 100,
            type: 'number',
            description: 'Rate limit: requests per window',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'security.rate_limit_window',
            value: 60,
            type: 'number',
            description: 'Rate limit: window in seconds',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'security.cors_origins',
            value: ['http://localhost:3000', 'http://localhost:3001'],
            type: 'json',
            description: 'Allowed CORS origins',
            isPublic: false,
            isSystem: false
        },

        // Email settings
        {
            key: 'email.from_name',
            value: 'Your App',
            type: 'string',
            description: 'Email sender name',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'email.from_address',
            value: 'noreply@yourapp.com',
            type: 'string',
            description: 'Email sender address',
            isPublic: false,
            isSystem: false
        },
        {
            key: 'email.smtp_enabled',
            value: false,
            type: 'boolean',
            description: 'Enable SMTP email sending',
            isPublic: false,
            isSystem: false
        },

        // Feature flags
        {
            key: 'features.registration_enabled',
            value: true,
            type: 'boolean',
            description: 'Allow new user registration',
            isPublic: true,
            isSystem: false
        },
        {
            key: 'features.social_login_enabled',
            value: false,
            type: 'boolean',
            description: 'Enable social media login',
            isPublic: true,
            isSystem: false
        },
        {
            key: 'features.two_factor_enabled',
            value: true,
            type: 'boolean',
            description: 'Enable two-factor authentication',
            isPublic: true,
            isSystem: false
        },
        {
            key: 'features.audit_logging_enabled',
            value: true,
            type: 'boolean',
            description: 'Enable audit logging',
            isPublic: false,
            isSystem: false
        },

        // System settings
        {
            key: 'system.maintenance_mode',
            value: {
                enabled: false,
                message: 'System is under maintenance. Please try again later.',
                allowedIPs: [],
                enabledAt: null,
                enabledBy: null
            },
            type: 'json',
            description: 'Maintenance mode configuration',
            isPublic: false,
            isSystem: true
        },
        {
            key: 'system.backup_retention_days',
            value: 30,
            type: 'number',
            description: 'Backup retention period in days',
            isPublic: false,
            isSystem: true
        },
        {
            key: 'system.log_retention_days',
            value: 90,
            type: 'number',
            description: 'Log retention period in days',
            isPublic: false,
            isSystem: true
        }
    ]

    for (const settingData of settings) {
        await prisma.setting.upsert({
            where: { key: settingData.key },
            update: {
                value: settingData.value,
                type: settingData.type,
                description: settingData.description,
                isPublic: settingData.isPublic,
                isSystem: settingData.isSystem
            },
            create: settingData
        })
        console.log(`✅ Setting '${settingData.key}' seeded`)
    }
}

async function seedAuditLogs() {
    console.log('📝 Seeding sample audit logs...')

    const adminUser = await prisma.user.findUnique({
        where: { email: 'admin@example.com' }
    })

    const testUser = await prisma.user.findUnique({
        where: { email: 'user@example.com' }
    })

    if (!adminUser || !testUser) {
        console.log('⚠️  Users not found, skipping audit logs seeding')
        return
    }

    const auditLogs = [
        {
            userId: adminUser.id,
            action: 'user_login',
            resource: 'user',
            resourceId: adminUser.id,
            method: 'POST',
            endpoint: '/api/auth/login',
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            success: true,
            createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000) // 2 hours ago
        },
        {
            userId: testUser.id,
            action: 'user_login',
            resource: 'user',
            resourceId: testUser.id,
            method: 'POST',
            endpoint: '/api/auth/login',
            ipAddress: '192.168.1.100',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            success: true,
            createdAt: new Date(Date.now() - 1 * 60 * 60 * 1000) // 1 hour ago
        },
        {
            userId: null,
            action: 'login_attempt_invalid_email',
            resource: 'auth',
            resourceId: null,
            method: 'POST',
            endpoint: '/api/auth/login',
            ipAddress: '192.168.1.200',
            userAgent: 'curl/7.68.0',
            success: false,
            errorMessage: 'Invalid credentials',
            newData: { email: 'hacker@evil.com' },
            createdAt: new Date(Date.now() - 30 * 60 * 1000) // 30 minutes ago
        },
        {
            userId: adminUser.id,
            action: 'setting_updated',
            resource: 'setting',
            resourceId: 'features.registration_enabled',
            method: 'PUT',
            endpoint: '/api/admin/settings/features.registration_enabled',
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            success: true,
            oldData: { value: false },
            newData: { value: true },
            createdAt: new Date(Date.now() - 15 * 60 * 1000) // 15 minutes ago
        }
    ]

    for (const logData of auditLogs) {
        await prisma.auditLog.create({
            data: logData
        })
    }

    console.log(`✅ ${auditLogs.length} audit logs seeded`)
}

async function seedUserSessions() {
    console.log('🔑 Seeding user sessions...')

    const users = await prisma.user.findMany({
        where: {
            isActive: true,
            isVerified: true
        },
        take: 3
    })

    for (const user of users) {
        const session = await prisma.userSession.create({
            data: {
                userId: user.id,
                refreshToken: `refresh_${nanoid(32)}`,
                fingerprint: nanoid(16),
                ipAddress: user.email.includes('admin') ? '127.0.0.1' : '192.168.1.100',
                userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                deviceType: 'desktop',
                deviceName: 'MacBook Pro',
                location: {
                    country: 'United States',
                    city: 'San Francisco',
                    region: 'California'
                },
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                lastUsedAt: new Date()
            }
        })
        console.log(`✅ Session created for user '${user.email}'`)
    }
}

async function cleanupExpiredData() {
    console.log('🧹 Cleaning up expired data...')

    // Clean up expired sessions
    const expiredSessions = await prisma.userSession.deleteMany({
        where: {
            expiresAt: {
                lt: new Date()
            }
        }
    })

    // Clean up expired revoked tokens
    const expiredTokens = await prisma.revokedToken.deleteMany({
        where: {
            expiresAt: {
                lt: new Date()
            }
        }
    })

    // Clean up old audit logs (older than 90 days)
    const oldAuditLogs = await prisma.auditLog.deleteMany({
        where: {
            createdAt: {
                lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)
            }
        }
    })

    console.log(`✅ Cleanup completed:`)
    console.log(`   - Expired sessions: ${expiredSessions.count}`)
    console.log(`   - Expired tokens: ${expiredTokens.count}`)
    console.log(`   - Old audit logs: ${oldAuditLogs.count}`)
}

async function main() {
    console.log('🌱 Starting database seeding...')

    try {
        await seedRoles()
        await seedUsers()
        await seedSettings()
        await seedAuditLogs()
        await seedUserSessions()
        await cleanupExpiredData()

        console.log('✅ Database seeding completed successfully!')
    } catch (error) {
        console.error('❌ Error during seeding:', error)
        process.exit(1)
    } finally {
        await prisma.$disconnect()
    }
}


async function runSeeder() {
    console.log('🌱 Starting database seeding...')

    try {
        await main()
        console.log('✅ Database seeding completed successfully!')
        process.exit(0)
    } catch (error) {
        console.error('❌ Seeding failed:', error)
        process.exit(1)
    }
}

runSeeder()


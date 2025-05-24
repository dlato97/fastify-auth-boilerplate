import type { FastifyRequest, FastifyReply } from 'fastify'
import { db, prisma } from '@/utils/database.js'
import { authLogger } from '@/utils/logger.js'
import { paginationSchema, createRoleSchema, updateRoleSchema } from '@/schemas/auth.schemas.js'

// Available permissions in the system
const AVAILABLE_PERMISSIONS = {
  users: {
    displayName: 'User Management',
    permissions: [
      { key: 'users:read', description: 'View users', level: 'read' },
      { key: 'users:write', description: 'Create and update users', level: 'write' },
      { key: 'users:delete', description: 'Delete users', level: 'delete' },
      { key: 'users:manage', description: 'Full user management', level: 'manage' }
    ]
  },
  roles: {
    displayName: 'Role Management',
    permissions: [
      { key: 'roles:read', description: 'View roles', level: 'read' },
      { key: 'roles:write', description: 'Create and update roles', level: 'write' },
      { key: 'roles:delete', description: 'Delete roles', level: 'delete' },
      { key: 'roles:manage', description: 'Full role management', level: 'manage' }
    ]
  },
  system: {
    displayName: 'System Administration',
    permissions: [
      { key: 'system:admin', description: 'System administration access', level: 'admin' },
      { key: 'system:settings', description: 'Manage system settings', level: 'admin' },
      { key: 'system:maintenance', description: 'System maintenance operations', level: 'admin' }
    ]
  },
  analytics: {
    displayName: 'Analytics',
    permissions: [
      { key: 'analytics:view', description: 'View analytics and reports', level: 'read' },
      { key: 'analytics:export', description: 'Export analytics data', level: 'write' }
    ]
  },
  audit: {
    displayName: 'Audit Logs',
    permissions: [
      { key: 'audit:read', description: 'View audit logs', level: 'read' },
      { key: 'audit:export', description: 'Export audit logs', level: 'write' }
    ]
  },
  settings: {
    displayName: 'Settings',
    permissions: [
      { key: 'settings:read', description: 'View settings', level: 'read' },
      { key: 'settings:write', description: 'Modify settings', level: 'write' }
    ]
  },
  profile: {
    displayName: 'Profile Management',
    permissions: [
      { key: 'profile:read', description: 'View own profile', level: 'read' },
      { key: 'profile:write', description: 'Update own profile', level: 'write' }
    ]
  }
}

export class RoleController {
  // Get paginated list of roles
  async getRoles(request: FastifyRequest, reply: FastifyReply) {
    try {
      const query = paginationSchema
        .extend({
          search: { optional: true },
          isActive: { optional: true },
          isSystem: { optional: true },
          sortBy: { optional: true },
          sortOrder: { optional: true }
        })
        .parse(request.query)

      // Build where clause
      const where: any = {}

      if (query.search) {
        where.OR = [
          { name: { contains: query.search, mode: 'insensitive' } },
          { displayName: { contains: query.search, mode: 'insensitive' } },
          { description: { contains: query.search, mode: 'insensitive' } }
        ]
      }

      if (query.isActive !== undefined) where.isActive = query.isActive
      if (query.isSystem !== undefined) where.isSystem = query.isSystem

      // Build order by
      const orderBy: any = {}
      if (query.sortBy) {
        orderBy[query.sortBy] = query.sortOrder || 'asc'
      } else {
        orderBy.name = 'asc'
      }

      // Get total count
      const total = await prisma.role.count({ where })

      // Get roles
      const roles = await prisma.role.findMany({
        where,
        orderBy,
        skip: (query.page - 1) * query.limit,
        take: query.limit,
        include: {
          _count: {
            select: { users: true }
          }
        }
      })

      const paginatedResult = db.paginate(roles, query.page, query.limit, total)

      // Create audit log
      await db.createAuditLog({
        userId: request.user?.id,
        action: 'roles_listed',
        resource: 'role',
        ipAddress: request.ip,
        success: true,
        metadata: {
          filters: query,
          resultCount: roles.length
        }
      })

      return reply.send(paginatedResult)
    } catch (error: any) {
      authLogger.error(error, 'Failed to get roles')
      return reply.code(500).send({
        error: 'Roles Fetch Failed',
        message: error.message
      })
    }
  }

  // Get role by ID
  async getRoleById(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string }

      const role = await prisma.role.findUnique({
        where: { id },
        include: {
          parent: {
            select: {
              id: true,
              name: true,
              displayName: true
            }
          },
          children: {
            select: {
              id: true,
              name: true,
              displayName: true
            }
          },
          _count: {
            select: { users: true }
          }
        }
      })

      if (!role) {
        return reply.code(404).send({
          error: 'Role Not Found',
          message: 'Role with specified ID not found'
        })
      }

      // Create audit log
      await db.createAuditLog({
        userId: request.user?.id,
        action: 'role_viewed',
        resource: 'role',
        resourceId: id,
        ipAddress: request.ip,
        success: true
      })

      return reply.send({ role })
    } catch (error: any) {
      authLogger.error(error, 'Failed to get role by ID')
      return reply.code(500).send({
        error: 'Role Fetch Failed',
        message: error.message
      })
    }
  }

  // Create new role
  async createRole(request: FastifyRequest, reply: FastifyReply) {
    try {
      const data = createRoleSchema.parse(request.body)

      // Check if role name already exists
      const existingRole = await prisma.role.findUnique({
        where: { name: data.name }
      })

      if (existingRole) {
        return reply.code(400).send({
          error: 'Role Exists',
          message: 'Role with this name already exists'
        })
      }

      // Validate parent role if provided
      if (data.parentId) {
        const parentRole = await prisma.role.findUnique({
          where: { id: data.parentId }
        })

        if (!parentRole) {
          return reply.code(400).send({
            error: 'Invalid Parent',
            message: 'Parent role not found'
          })
        }
      }

      // Validate permissions
      const allPermissions = Object.values(AVAILABLE_PERMISSIONS).flatMap(category =>
        category.permissions.map(p => p.key)
      )

      const invalidPermissions = data.permissions.filter(p => !allPermissions.includes(p))
      if (invalidPermissions.length > 0) {
        return reply.code(400).send({
          error: 'Invalid Permissions',
          message: `Invalid permissions: ${invalidPermissions.join(', ')}`
        })
      }

      // Create role
      const role = await prisma.role.create({
        data: {
          name: data.name,
          displayName: data.displayName,
          description: data.description,
          color: data.color,
          permissions: data.permissions,
          parentId: data.parentId,
          metadata: data.metadata,
          isSystem: false,
          isActive: true
        }
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user?.id,
        action: 'role_created',
        resource: 'role',
        resourceId: role.id,
        ipAddress: request.ip,
        success: true,
        newData: {
          name: role.name,
          permissions: data.permissions
        }
      })

      authLogger.info(
        {
          adminId: request.user?.id,
          roleId: role.id,
          roleName: role.name
        },
        'Role created'
      )

      return reply.code(201).send({
        message: 'Role created successfully',
        role
      })
    } catch (error: any) {
      authLogger.error(error, 'Failed to create role')
      return reply.code(400).send({
        error: 'Role Creation Failed',
        message: error.message
      })
    }
  }

  // Update role
  async updateRole(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string }
      const data = updateRoleSchema.parse(request.body)

      // Check if role exists
      const existingRole = await prisma.role.findUnique({
        where: { id }
      })

      if (!existingRole) {
        return reply.code(404).send({
          error: 'Role Not Found',
          message: 'Role with specified ID not found'
        })
      }

      // Prevent modification of system roles
      if (existingRole.isSystem) {
        return reply.code(400).send({
          error: 'System Role',
          message: 'Cannot modify system roles'
        })
      }

      // Check name uniqueness if changing
      if (data.name && data.name !== existingRole.name) {
        const nameExists = await prisma.role.findFirst({
          where: {
            name: data.name,
            id: { not: id }
          }
        })

        if (nameExists) {
          return reply.code(400).send({
            error: 'Name Taken',
            message: 'Role name is already in use'
          })
        }
      }

      // Validate parent role if changing
      if (data.parentId && data.parentId !== existingRole.parentId) {
        // Prevent circular references
        if (data.parentId === id) {
          return reply.code(400).send({
            error: 'Circular Reference',
            message: 'Role cannot be its own parent'
          })
        }

        const parentRole = await prisma.role.findUnique({
          where: { id: data.parentId }
        })

        if (!parentRole) {
          return reply.code(400).send({
            error: 'Invalid Parent',
            message: 'Parent role not found'
          })
        }
      }

      // Validate permissions if provided
      if (data.permissions) {
        const allPermissions = Object.values(AVAILABLE_PERMISSIONS).flatMap(category =>
          category.permissions.map(p => p.key)
        )

        const invalidPermissions = data.permissions.filter(p => !allPermissions.includes(p))
        if (invalidPermissions.length > 0) {
          return reply.code(400).send({
            error: 'Invalid Permissions',
            message: `Invalid permissions: ${invalidPermissions.join(', ')}`
          })
        }
      }

      // Update role
      const updatedRole = await prisma.role.update({
        where: { id },
        data
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user?.id,
        action: 'role_updated',
        resource: 'role',
        resourceId: id,
        ipAddress: request.ip,
        success: true,
        oldData: {
          name: existingRole.name,
          permissions: existingRole.permissions
        },
        newData: data
      })

      return reply.send({
        message: 'Role updated successfully',
        role: updatedRole
      })
    } catch (error: any) {
      authLogger.error(error, 'Failed to update role')
      return reply.code(400).send({
        error: 'Role Update Failed',
        message: error.message
      })
    }
  }

  // Delete role
  async deleteRole(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string }

      // Check if role exists
      const role = await prisma.role.findUnique({
        where: { id },
        include: {
          _count: {
            select: { users: true }
          }
        }
      })

      if (!role) {
        return reply.code(404).send({
          error: 'Role Not Found',
          message: 'Role with specified ID not found'
        })
      }

      // Prevent deletion of system roles
      if (role.isSystem) {
        return reply.code(400).send({
          error: 'System Role',
          message: 'Cannot delete system roles'
        })
      }

      // Check if role is in use
      if (role._count.users > 0) {
        return reply.code(400).send({
          error: 'Role In Use',
          message: `Role is assigned to ${role._count.users} user(s). Remove all assignments first.`
        })
      }

      // Delete role
      await prisma.role.delete({
        where: { id }
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user?.id,
        action: 'role_deleted',
        resource: 'role',
        resourceId: id,
        ipAddress: request.ip,
        success: true,
        oldData: {
          name: role.name,
          permissions: role.permissions
        }
      })

      authLogger.info(
        {
          adminId: request.user?.id,
          roleId: id,
          roleName: role.name
        },
        'Role deleted'
      )

      return reply.send({
        message: 'Role deleted successfully'
      })
    } catch (error: any) {
      authLogger.error(error, 'Failed to delete role')
      return reply.code(500).send({
        error: 'Role Deletion Failed',
        message: error.message
      })
    }
  }

  // Get users with specific role
  async getRoleUsers(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string }
      const query = paginationSchema
        .extend({
          isActive: { optional: true }
        })
        .parse(request.query)

      // Check if role exists
      const role = await prisma.role.findUnique({
        where: { id }
      })

      if (!role) {
        return reply.code(404).send({
          error: 'Role Not Found',
          message: 'Role with specified ID not found'
        })
      }

      // Build where clause
      const where: any = {
        roles: {
          some: { roleId: id }
        }
      }

      if (query.isActive !== undefined) where.isActive = query.isActive

      // Get total count
      const total = await prisma.user.count({ where })

      // Get users
      const users = await prisma.user.findMany({
        where,
        skip: (query.page - 1) * query.limit,
        take: query.limit,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          username: true,
          isActive: true,
          isVerified: true,
          createdAt: true,
          roles: {
            where: { roleId: id },
            select: {
              assignedAt: true,
              expiresAt: true,
              assignedBy: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      })

      const paginatedResult = db.paginate(users, query.page, query.limit, total)

      return reply.send(paginatedResult)
    } catch (error: any) {
      authLogger.error(error, 'Failed to get role users')
      return reply.code(500).send({
        error: 'Role Users Fetch Failed',
        message: error.message
      })
    }
  }

  // Get available permissions
  async getAvailablePermissions(request: FastifyRequest, reply: FastifyReply) {
    try {
      const permissions = Object.values(AVAILABLE_PERMISSIONS).flatMap(
        category => category.permissions
      )

      const categories = Object.entries(AVAILABLE_PERMISSIONS).map(([key, category]) => ({
        name: key,
        displayName: category.displayName,
        permissions: category.permissions.map(p => p.key)
      }))

      return reply.send({
        permissions,
        categories
      })
    } catch (error: any) {
      authLogger.error(error, 'Failed to get available permissions')
      return reply.code(500).send({
        error: 'Permissions Fetch Failed',
        message: error.message
      })
    }
  }

  // Duplicate role
  async duplicateRole(request: FastifyRequest, reply: FastifyReply) {
    try {
      const { id } = request.params as { id: string }
      const { name, displayName, description } = request.body as {
        name: string
        displayName: string
        description?: string
      }

      // Check if source role exists
      const sourceRole = await prisma.role.findUnique({
        where: { id }
      })

      if (!sourceRole) {
        return reply.code(404).send({
          error: 'Source Role Not Found',
          message: 'Source role not found'
        })
      }

      // Check if new name already exists
      const existingRole = await prisma.role.findUnique({
        where: { name }
      })

      if (existingRole) {
        return reply.code(400).send({
          error: 'Role Exists',
          message: 'Role with this name already exists'
        })
      }

      // Create duplicated role
      const duplicatedRole = await prisma.role.create({
        data: {
          name,
          displayName,
          description: description || `Copy of ${sourceRole.displayName}`,
          color: sourceRole.color,
          permissions: sourceRole.permissions,
          parentId: sourceRole.parentId,
          metadata: sourceRole.metadata,
          isSystem: false,
          isActive: true
        }
      })

      // Create audit log
      await db.createAuditLog({
        userId: request.user?.id,
        action: 'role_duplicated',
        resource: 'role',
        resourceId: duplicatedRole.id,
        ipAddress: request.ip,
        success: true,
        metadata: {
          sourceRoleId: id,
          sourceRoleName: sourceRole.name
        }
      })

      return reply.code(201).send({
        message: 'Role duplicated successfully',
        role: duplicatedRole
      })
    } catch (error: any) {
      authLogger.error(error, 'Failed to duplicate role')
      return reply.code(400).send({
        error: 'Role Duplication Failed',
        message: error.message
      })
    }
  }

  // Get role hierarchy
  async getRoleHierarchy(request: FastifyRequest, reply: FastifyReply) {
    try {
      // Get all roles
      const roles = await prisma.role.findMany({
        where: { isActive: true },
        select: {
          id: true,
          name: true,
          displayName: true,
          parentId: true
        },
        orderBy: { name: 'asc' }
      })

      // Build hierarchy tree
      const buildHierarchy = (parentId: string | null = null, level = 0): any[] => {
        return roles
          .filter(role => role.parentId === parentId)
          .map(role => ({
            id: role.id,
            name: role.name,
            displayName: role.displayName,
            level,
            children: buildHierarchy(role.id, level + 1)
          }))
      }

      const hierarchy = buildHierarchy()

      return reply.send({ hierarchy })
    } catch (error: any) {
      authLogger.error(error, 'Failed to get role hierarchy')
      return reply.code(500).send({
        error: 'Hierarchy Fetch Failed',
        message: error.message
      })
    }
  }
}

export const roleController = new RoleController()

import type { FastifyInstance } from 'fastify'
import { roleController } from '@/controllers/role.controller'
import { authMiddleware } from '@/middleware/auth.middleware'

export async function roleRoutes(server: FastifyInstance) {
  // Get list of roles
  server.get(
    '/',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Get list of roles',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        querystring: {
          type: 'object',
          properties: {
            page: { type: 'integer', minimum: 1, default: 1 },
            limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
            search: { type: 'string' },
            isActive: { type: 'boolean' },
            isSystem: { type: 'boolean' },
            sortBy: { type: 'string', enum: ['name', 'displayName', 'createdAt'] },
            sortOrder: { type: 'string', enum: ['asc', 'desc'], default: 'asc' }
          }
        },
        response: {
          200: {
            type: 'object',
            properties: {
              data: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    displayName: { type: 'string' },
                    description: { type: 'string' },
                    color: { type: 'string' },
                    permissions: {
                      type: 'array',
                      items: { type: 'string' }
                    },
                    isSystem: { type: 'boolean' },
                    isActive: { type: 'boolean' },
                    createdAt: { type: 'string' },
                    updatedAt: { type: 'string' },
                    _count: {
                      type: 'object',
                      properties: {
                        users: { type: 'integer' }
                      }
                    }
                  }
                }
              },
              pagination: {
                type: 'object',
                properties: {
                  page: { type: 'integer' },
                  limit: { type: 'integer' },
                  total: { type: 'integer' },
                  totalPages: { type: 'integer' },
                  hasNext: { type: 'boolean' },
                  hasPrev: { type: 'boolean' }
                }
              }
            }
          }
        }
      }
    },
    roleController.getRoles.bind(roleController)
  )

  // Get specific role by ID
  server.get(
    '/:id',
    {
      preHandler: [authMiddleware.required],
      schema: {
        description: 'Get role by ID',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        params: {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string' }
          }
        }
      }
    },
    roleController.getRoleById.bind(roleController)
  )

  // Create new role (Admin only)
  server.post(
    '/',
    {
      preHandler: [authMiddleware.required, authMiddleware.systemAdmin],
      schema: {
        description: 'Create a new role',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        body: {
          type: 'object',
          required: ['name', 'displayName', 'permissions'],
          properties: {
            name: {
              type: 'string',
              pattern: '^[a-zA-Z0-9_-]+$',
              minLength: 1,
              maxLength: 50
            },
            displayName: {
              type: 'string',
              minLength: 1,
              maxLength: 100
            },
            description: {
              type: 'string',
              maxLength: 500
            },
            color: {
              type: 'string',
              pattern: '^#[0-9A-Fa-f]{6}$'
            },
            permissions: {
              type: 'array',
              items: { type: 'string' },
              minItems: 1
            },
            parentId: { type: 'string' },
            metadata: { type: 'object' }
          }
        }
      }
    },
    roleController.createRole.bind(roleController)
  )

  // Update role (Admin only)
  server.put(
    '/:id',
    {
      preHandler: [authMiddleware.required, authMiddleware.systemAdmin],
      schema: {
        description: 'Update role information',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        params: {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string' }
          }
        },
        body: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              pattern: '^[a-zA-Z0-9_-]+$',
              minLength: 1,
              maxLength: 50
            },
            displayName: {
              type: 'string',
              minLength: 1,
              maxLength: 100
            },
            description: {
              type: 'string',
              maxLength: 500
            },
            color: {
              type: 'string',
              pattern: '^#[0-9A-Fa-f]{6}$'
            },
            permissions: {
              type: 'array',
              items: { type: 'string' }
            },
            parentId: { type: 'string' },
            isActive: { type: 'boolean' },
            metadata: { type: 'object' }
          }
        }
      }
    },
    roleController.updateRole.bind(roleController)
  )

  // Delete role (Admin only)
  server.delete(
    '/:id',
    {
      preHandler: [authMiddleware.required, authMiddleware.systemAdmin],
      schema: {
        description: 'Delete a role',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        params: {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string' }
          }
        }
      }
    },
    roleController.deleteRole.bind(roleController)
  )

  // Get users with specific role
  server.get(
    '/:id/users',
    {
      preHandler: [authMiddleware.required, authMiddleware.readUsers],
      schema: {
        description: 'Get users assigned to specific role',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        params: {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string' }
          }
        },
        querystring: {
          type: 'object',
          properties: {
            page: { type: 'integer', minimum: 1, default: 1 },
            limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
            isActive: { type: 'boolean' }
          }
        }
      }
    },
    roleController.getRoleUsers.bind(roleController)
  )

  // Get available permissions
  server.get(
    '/permissions/available',
    {
      preHandler: [authMiddleware.required, authMiddleware.systemAdmin],
      schema: {
        description: 'Get list of available permissions',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        response: {
          200: {
            type: 'object',
            properties: {
              permissions: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    key: { type: 'string' },
                    description: { type: 'string' },
                    category: { type: 'string' },
                    level: { type: 'string', enum: ['read', 'write', 'delete', 'manage', 'admin'] }
                  }
                }
              },
              categories: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
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
    },
    roleController.getAvailablePermissions.bind(roleController)
  )

  // Duplicate role (Admin only)
  server.post(
    '/:id/duplicate',
    {
      preHandler: [authMiddleware.required, authMiddleware.systemAdmin],
      schema: {
        description: 'Duplicate an existing role',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        params: {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string' }
          }
        },
        body: {
          type: 'object',
          required: ['name', 'displayName'],
          properties: {
            name: {
              type: 'string',
              pattern: '^[a-zA-Z0-9_-]+$',
              minLength: 1,
              maxLength: 50
            },
            displayName: {
              type: 'string',
              minLength: 1,
              maxLength: 100
            },
            description: { type: 'string' }
          }
        }
      }
    },
    roleController.duplicateRole.bind(roleController)
  )

  // Get role hierarchy
  server.get(
    '/hierarchy',
    {
      preHandler: [authMiddleware.required, authMiddleware.systemAdmin],
      schema: {
        description: 'Get role hierarchy tree',
        tags: ['Role Management'],
        security: [{ bearerAuth: [] }],
        response: {
          200: {
            type: 'object',
            properties: {
              hierarchy: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    displayName: { type: 'string' },
                    level: { type: 'integer' },
                    children: {
                      type: 'array',
                      items: { type: 'object' }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    roleController.getRoleHierarchy.bind(roleController)
  )
}

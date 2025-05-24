import 'fastify'
import type { User, Role } from '@prisma/client'

export interface AuthUser extends User {
  roles: Array<{
    role: Role
  }>
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    user: AuthUser // Questo dovrebbe propagarsi a request.user
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthUser
    permissions?: string[]
  }
}

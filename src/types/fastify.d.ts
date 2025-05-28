import 'fastify'
import type { Role, User } from '@prisma/client'
import type { FastifyReply, FastifyRequest, HookHandlerDoneFunction } from 'fastify'

export type PreHandlerHook = (
  request: FastifyRequest,
  reply: FastifyReply,
  done?: HookHandlerDoneFunction
) => Promise<void> | void

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

import Fastify from 'fastify'
import { config } from '@/config/config.js'
import { registerPlugins } from '@/config/plugins.js'
import { registerRoutes } from '@/config/routes.js'
import { logger } from '@/utils/logger.js'
import { gracefulShutdown } from '@/utils/graceful-shutdown.js'
import { db } from '@/utils/database.js'
import { AppServer } from '@/types/server'
import * as crypto from 'node:crypto'

const server: AppServer = Fastify({
  logger: logger,
  trustProxy: true,
  bodyLimit: config.server.maxBodySize,
  keepAliveTimeout: 30000,
  requestIdHeader: 'x-request-id',
  requestIdLogLabel: 'reqId',
  genReqId: () => crypto.randomUUID()
})

async function start() {
  try {
    // Register plugins first
    await registerPlugins(server)

    await db.connect()

    // Then register routes
    await registerRoutes(server)

    // Global error handler
    server.setErrorHandler(async (error, request, reply) => {
      request.log.error(error, 'Unhandled error')

      if (reply.statusCode >= 500) {
        // Don't leak error details in production
        const message = config.isDevelopment ? error.message : 'Internal Server Error'

        return reply.send({
          error: 'Internal Server Error',
          message,
          statusCode: reply.statusCode,
          timestamp: new Date().toISOString(),
          requestId: request.id
        })
      }

      return reply.send({
        error: error.name || 'Error',
        message: error.message,
        statusCode: reply.statusCode,
        timestamp: new Date().toISOString(),
        requestId: request.id
      })
    })

    // Start server
    const address = await server.listen({
      port: config.server.port,
      host: config.server.host
    })

    logger.info(`🚀 Server listening at ${address}`)

    if (config.isDevelopment) {
      logger.info(`📚 Swagger UI available at ${address}/documentation`)
      logger.info(`🔍 Health check available at ${address}/health`)
    }

    // Setup graceful shutdown
    gracefulShutdown(server)
  } catch (error) {
    logger.error(error, 'Failed to start server')
    process.exit(1)
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', error => {
  logger.fatal(error, 'Uncaught exception')
  process.exit(1)
})

process.on('unhandledRejection', (reason, promise) => {
  logger.fatal({ reason, promise }, 'Unhandled rejection')
  process.exit(1)
})

await start()

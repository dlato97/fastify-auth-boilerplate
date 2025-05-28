import Fastify from 'fastify'
import { config } from '@/config/config.js'
import { logger } from '@/utils/logger.js'
import { gracefulShutdown } from '@/utils/graceful-shutdown.js'
import { db } from '@/utils/database.js'
import { AppServer } from '@/types/server'
import * as crypto from 'node:crypto'
import { registerRoutes } from './config/routes'
import { registerPlugins } from './config/plugins'

const server: AppServer = Fastify({
  loggerInstance: logger,
  trustProxy: true,
  bodyLimit: config.server.maxBodySize,
  keepAliveTimeout: 30000,
  requestIdHeader: 'x-request-id',
  requestIdLogLabel: 'reqId',
  genReqId: () => crypto.randomUUID()
})

async function start() {
  try {
    logger.info('🚀 Starting server...')

    // Register plugins first
    logger.info('📦 Registering plugins...')
    await registerPlugins(server)
    logger.info('✅ Plugins registered successfully')

    // Connect to database
    logger.info('🗄️ Connecting to database...')
    await db.connect()
    logger.info('✅ Database connected successfully')

    // Register routes (this will set up detailed error handlers)
    logger.info('🛣️ Registering routes...')
    await registerRoutes(server)
    logger.info('✅ Routes registered successfully')

    // Start server
    const address = await server.listen({
      port: config.server.port,
      host: config.server.host
    })

    logger.info(`🚀 Server listening at ${address}`)

    if (config.isDevelopment) {
      logger.info(`📚 Swagger UI available at ${address}/documentation`)
      logger.info(`🔍 Health check available at ${address}/health`)

      // Print all registered routes
      logger.info('📋 Registered routes:')
      console.log(server.printRoutes())
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

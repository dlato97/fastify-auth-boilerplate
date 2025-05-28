import { logger } from './logger.js'
//import { redisClient } from './redis.js'
import { db, prisma } from './database.js'
import { AppServer } from '@/types/server'

export function gracefulShutdown(server: AppServer) {
  const gracefulShutdownHandler = async (signal: string) => {
    logger.info(`Received ${signal}, starting graceful shutdown...`)

    const shutdownTimeout = setTimeout(() => {
      logger.error('Graceful shutdown timeout, forcing exit')
      process.exit(1)
    }, 30000) // 30 seconds timeout

    try {
      // 1. Stop accepting new requests
      logger.info('Stopping server from accepting new requests...')
      await server.close()

      // 2. Close database connections
      logger.info('Closing database connections...')
      await prisma.$disconnect()

      // 3. Close Redis connection
      logger.info('Closing Redis connection...')
      // await redisClient.quit()

      // 4. Additional cleanup can go here
      // - Close other database connections
      // - Flush logs
      // - Save in-memory data
      // - Notify external services
      await db.disconnect()

      logger.info('✅ Graceful shutdown completed')
      clearTimeout(shutdownTimeout)
      process.exit(0)
    } catch (error) {
      logger.error(error, 'Error during graceful shutdown')
      clearTimeout(shutdownTimeout)
      process.exit(1)
    }
  }

  const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'] as const

  const handleGracefulShutdown = (signal: string) => {
    gracefulShutdownHandler(signal)
      .then(() => {
        logger.info(`Graceful shutdown completed for ${signal}`)
        process.exit(0)
      })
      .catch(error => {
        logger.error(`Error during graceful shutdown (${signal}):`, error)
        process.exit(1)
      })
  }

  // Register all shutdown handlers
  signals.forEach(signal => {
    process.on(signal, () => handleGracefulShutdown(signal))
  })
}

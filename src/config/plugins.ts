import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import rateLimit from '@fastify/rate-limit'
import swagger from '@fastify/swagger'
import swaggerUi from '@fastify/swagger-ui'
import sensible from '@fastify/sensible'
import underPressure from '@fastify/under-pressure'
import cookie from '@fastify/cookie'
import formbody from '@fastify/formbody'
import multipart from '@fastify/multipart'
import jwt from '@fastify/jwt'

import { config } from './config.js'
import { AppServer } from '@/types/server.js'
import { db } from '@/utils/database'

//import { redisClient } from '@/utils/redis.js'

export async function registerPlugins(server: AppServer) {
  // Security plugins
  await server.register(helmet, {
    contentSecurityPolicy: config.isDevelopment
      ? false
      : {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:', 'https:']
          }
        }
  })

  await server.register(cors, {
    origin: config.server.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })

  // Rate limiting with Redis store
  await server.register(rateLimit, {
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.timeWindow,
    //redis: redisClient,
    keyGenerator: request => {
      return `rate_limit:${request.ip}:${request.routeOptions.schema ? JSON.stringify(request.routeOptions.schema) : 'unknown'}`
    },
    errorResponseBuilder: (request, context) => ({
      error: 'Too Many Requests',
      message: `Rate limit exceeded, retry in ${Math.round(context.ttl / 1000)} seconds`,
      statusCode: 429,
      timestamp: new Date().toISOString(),
      requestId: request.id
    })
  })

  // Health monitoring
  await server.register(underPressure, {
    maxEventLoopDelay: 1000,
    maxHeapUsedBytes: 1000000000, // 1GB
    maxRssBytes: 1000000000, // 1GB
    maxEventLoopUtilization: 0.98,
    message: 'Under pressure!',
    retryAfter: 50,
    healthCheck: async () => {
      // Check database connection
      try {
        //await redisClient.ping()
        await db.isHealthy()
        return true
      } catch {
        return false
      }
    },
    healthCheckInterval: 5000
  })

  // JWT Authentication
  await server.register(jwt, {
    secret: {
      private: config.jwt.accessSecret,
      public: config.jwt.accessSecret
    },
    sign: {
      expiresIn: config.jwt.accessExpiresIn
    },
    cookie: {
      cookieName: 'token',
      signed: false
    }
  })

  // Refresh token JWT
  await server.register(jwt, {
    namespace: 'refresh',
    secret: {
      private: config.jwt.refreshSecret,
      public: config.jwt.refreshSecret
    },
    sign: {
      expiresIn: config.jwt.refreshExpiresIn
    }
  })

  // Utility plugins
  await server.register(sensible)

  await server.register(cookie, {
    secret: config.security.sessionSecret,
    parseOptions: {
      httpOnly: true,
      secure: config.isProduction,
      sameSite: config.isProduction ? 'strict' : 'lax'
    }
  })

  await server.register(formbody)

  await server.register(multipart, {
    limits: {
      fileSize: config.upload.maxFileSize
    }
  })

  // Swagger documentation (only in development)
  if (config.features.swagger && config.isDevelopment) {
    await server.register(swagger, {
      openapi: {
        openapi: '3.0.0',
        info: {
          title: 'Fastify Auth API',
          description: 'Modern authentication API with RBAC',
          version: '1.0.0',
          contact: {
            name: 'API Support',
            email: 'support@example.com'
          },
          license: {
            name: 'MIT',
            url: 'https://opensource.org/licenses/MIT'
          }
        },
        servers: [
          {
            url: config.urls.app,
            description: 'Development server'
          }
        ],
        components: {
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT'
            }
          }
        },
        security: [
          {
            bearerAuth: []
          }
        ]
      }
    })

    await server.register(swaggerUi, {
      routePrefix: '/documentation',
      uiConfig: {
        docExpansion: 'list',
        deepLinking: false,
        defaultModelRendering: 'model'
      },
      staticCSP: true,
      transformStaticCSP: header => header,
      transformSpecification: swaggerObject => {
        return swaggerObject
      },
      transformSpecificationClone: true
    })
  }

  // Global request logging
  if (config.logging.enableRequestLogging) {
    server.addHook('onRequest', async request => {
      request.log.info(
        {
          method: request.method,
          url: request.url,
          userAgent: request.headers['user-agent'],
          ip: request.ip
        },
        'Incoming request'
      )
    })
    server.addHook('onResponse', async (request, reply) => {
      request.log.info(
        {
          method: request.method,
          url: request.url,
          statusCode: reply.statusCode,
          responseTime: reply.elapsedTime
        },
        'Request completed'
      )
    })

    server.addHook('onError', async (request, _reply, error) => {
      request.log.error(
        {
          method: request.method,
          url: request.url,
          error: error.message,
          stack: error.stack
        },
        'Request failed with error'
      )
    })
  }
}

import { createClient } from 'redis'
import { config } from '@/config/config.js'
import { logger } from './logger.js'

export const redisClient = createClient({
  url: config.redis.url,
  socket: {
    connectTimeout: 5000,
    // lazyConnect: true,
    reconnectStrategy: retries => {
      if (retries > 10) {
        logger.error('Redis connection failed after 10 retries')
        return false
      }
      return Math.min(retries * 50, 1000)
    }
  }
})

redisClient.on('connect', () => {
  logger.info('🔗 Redis client connected')
})

redisClient.on('ready', () => {
  logger.info('✅ Redis client ready')
})

redisClient.on('error', error => {
  logger.error(error, '❌ Redis client error')
})

redisClient.on('reconnecting', () => {
  logger.warn('🔄 Redis client reconnecting')
})

redisClient.on('end', () => {
  logger.info('❌ Redis client disconnected')
})

// Connect to Redis
export async function connectRedis() {
  try {
    await redisClient.connect()
    logger.info('Redis connection established')
  } catch (error) {
    logger.error(error, 'Failed to connect to Redis')
    throw error
  }
}

// Redis utility functions
export const redis = {
  // Basic operations
  get: (key: string) => redisClient.get(key),
  set: (key: string, value: string, ttl?: number) =>
    ttl ? redisClient.setEx(key, ttl, value) : redisClient.set(key, value),
  del: (key: string) => redisClient.del(key),
  exists: (key: string) => redisClient.exists(key),
  expire: (key: string, ttl: number) => redisClient.expire(key, ttl),
  ttl: (key: string) => redisClient.ttl(key),

  // JSON operations
  setJSON: (key: string, value: any, ttl?: number) =>
    ttl
      ? redisClient.setEx(key, ttl, JSON.stringify(value))
      : redisClient.set(key, JSON.stringify(value)),
  getJSON: async <T>(key: string): Promise<T | null> => {
    const value = await redisClient.get(key)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return value ? JSON.parse(value) : null
  },

  // Hash operations
  hSet: (key: string, field: string, value: string) => redisClient.hSet(key, field, value),
  hGet: (key: string, field: string) => redisClient.hGet(key, field),
  hGetAll: (key: string) => redisClient.hGetAll(key),
  hDel: (key: string, field: string) => redisClient.hDel(key, field),

  // Set operations
  sAdd: (key: string, member: string) => redisClient.sAdd(key, member),
  sRem: (key: string, member: string) => redisClient.sRem(key, member),
  sIsMember: (key: string, member: string) => redisClient.sIsMember(key, member),
  sMembers: (key: string) => redisClient.sMembers(key),

  // List operations
  lPush: (key: string, value: string) => redisClient.lPush(key, value),
  rPush: (key: string, value: string) => redisClient.rPush(key, value),
  lPop: (key: string) => redisClient.lPop(key),
  rPop: (key: string) => redisClient.rPop(key),
  lRange: (key: string, start: number, stop: number) => redisClient.lRange(key, start, stop),

  // Pattern operations
  keys: (pattern: string) => redisClient.keys(pattern),
  scan: (cursor: number, pattern?: string, count?: number) =>
    redisClient.scan(cursor, pattern ? { MATCH: pattern, COUNT: count } : { COUNT: count }),

  // Utility functions
  ping: () => redisClient.ping(),
  flushDB: () => redisClient.flushDb(),
  info: () => redisClient.info(),

  // Session management
  setSession: (sessionId: string, data: any, ttl: number = 3600) =>
    redis.setJSON(`session:${sessionId}`, data, ttl),
  getSession: <T>(sessionId: string) => redis.getJSON<T>(`session:${sessionId}`),
  deleteSession: (sessionId: string) => redis.del(`session:${sessionId}`),

  // Token blacklist
  blacklistToken: (jti: string, ttl: number) => redis.set(`blacklist:${jti}`, '1', ttl),
  isTokenBlacklisted: async (jti: string) => (await redis.exists(`blacklist:${jti}`)) === 1,

  // Rate limiting
  incrementRateLimit: async (key: string, window: number, limit: number) => {
    const current = await redisClient.incr(key)
    if (current === 1) {
      await redisClient.expire(key, window)
    }
    return {
      count: current,
      remaining: Math.max(0, limit - current),
      resetTime: current === 1 ? Date.now() + window * 1000 : null
    }
  },

  // Cache with automatic JSON serialization
  cache: {
    set: <T>(key: string, value: T, ttl?: number) => redis.setJSON(`cache:${key}`, value, ttl),
    get: <T>(key: string) => redis.getJSON<T>(`cache:${key}`),
    del: (key: string) => redis.del(`cache:${key}`),
    invalidatePattern: async (pattern: string) => {
      const keys = await redis.keys(`cache:${pattern}`)
      if (keys.length > 0) {
        await redisClient.del(keys)
      }
    }
  }
}

export default redis

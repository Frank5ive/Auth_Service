// server.js
import Fastify from 'fastify';
import dotenv from 'dotenv';
import prismaPlugin from './plugins/prisma.js';
import redisPlugin from './plugins/redis.js';
import cookie from '@fastify/cookie';
import authRoutes from './routes/authRoutes.js';
import rateLimiter from './middleware/rateLimiter.js';

// Load environment variables
dotenv.config();

// Create Fastify instance with pretty logging
const fastify = Fastify({
  logger: {
    transport: {
      target: 'pino-pretty',
      options: {
        translateTime: 'HH:MM:ss Z',
        ignore: 'pid,hostname',
        colorize: true,
        messageFormat: '{msg} [id={reqId}]'
      }
    }
  }
});

try {
  // Register plugins
  fastify.log.info('🔌 Initializing plugins...');
  await fastify.register(rateLimiter);
  await fastify.register(prismaPlugin);
  await fastify.register(redisPlugin);
  await fastify.register(cookie, { secret: process.env.COOKIE_SECRET });
  await fastify.register(authRoutes, { prefix: '/api/auth'});
  fastify.log.info('✅ All plugins registered successfully');

  // Example route to test Redis
  fastify.get('/cache', async (req, reply) => {
    await fastify.redis.set('foo', 'bar');
    const value = await fastify.redis.get('foo');
    return { foo: value };
  });

  // Start server
  const port = process.env.PORT || 3000;
  fastify.log.info(`📡 Starting server on port ${port}...`);
  const address = await fastify.listen({ port });
  fastify.log.info(`🚀 Server is ready at ${address}`);
} catch (err) {
  fastify.log.error('❌ Server failed to start:');
  fastify.log.error(err);
  process.exit(1);
}

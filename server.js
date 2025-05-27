// server.js
import Fastify from 'fastify';
import dotenv from 'dotenv';
import prismaPlugin from './plugins/prisma.js';
import redisPlugin from './plugins/redis.js';
import cookie from '@fastify/cookie';
import authRoutes from './routes/authRoutes.js';

// Load environment variables
dotenv.config();

// Create Fastify instance with logging
const fastify = Fastify({ logger: true });

try {
  // Register plugins
  await fastify.register(prismaPlugin);
  await fastify.register(redisPlugin);
  await fastify.register(cookie, { secret: process.env.COOKIE_SECRET });
  await fastify.register(authRoutes, { prefix: '/api/auth'});
  // Example route to test Redis
  fastify.get('/cache', async (req, reply) => {
    await fastify.redis.set('foo', 'bar');
    const value = await fastify.redis.get('foo');
    return { foo: value };
  });

  // Start server
  const address = await fastify.listen({ port: process.env.PORT || 3000 });
  fastify.log.info(`🚀 Server listening at ${address}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}

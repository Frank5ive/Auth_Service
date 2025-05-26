// plugins/redis.js
import fp from 'fastify-plugin';
import { createClient } from 'redis';

export default fp(async function (fastify, opts) {
  const client = createClient({
    socket: {
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT),
      tls: {} // ✅ Required for Redis Cloud SSL connection
    },
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD
  });

  client.on('error', (err) => {
    fastify.log.error(`❌ Redis connection error: ${err.message}`);
  });

  client.on('connect', () => {
    fastify.log.info('✅ Redis connected');
  });

  await client.connect();

  // Decorate Fastify with Redis client
  fastify.decorate('redis', client);
});

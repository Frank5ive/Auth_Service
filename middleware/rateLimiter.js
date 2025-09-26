import { TooManyRequestsError } from '../utils/errors.js';

// middlewares/rateLimiter.js
export default async function rateLimiter(fastify) {
  fastify.addHook('onRequest', async (req, reply) => {
    const ip = req.ip;
    const key = `rate:${ip}`;
    const max = 100;
    const ttl = 900;

    const count = await fastify.redis.incr(key);
    if (count === 1) await fastify.redis.expire(key, ttl);
    if (count > max) {
      throw new TooManyRequestsError('Too many requests', 'TOO_MANY_REQUESTS');
    }
  });
}

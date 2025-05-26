// plugins/prisma.js
import fp from 'fastify-plugin';
import { PrismaClient } from '../generated/prisma/index.js';

async function prismaPlugin(fastify, options) {
  const prisma = new PrismaClient();

  await prisma.$connect();
  fastify.log.info('✅ Prisma connected to the database.');

  fastify.decorate('prisma', prisma);

  fastify.addHook('onClose', async (fastify, done) => {
    await fastify.prisma.$disconnect();
    fastify.log.info('🛑 Prisma disconnected from the database.');
  });
}

export default fp(prismaPlugin);

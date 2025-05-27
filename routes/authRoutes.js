import * as authController from '../controllers/authController.js';

export default async function authRoutes(fastify) {
  fastify.post('/register', authController.register);
  fastify.post('/verify-otp', authController.verifyOTP); // ✅ New route
  fastify.post('/login', authController.login);
  fastify.post('/logout', authController.logout);
  fastify.post('/renew-token', authController.renewToken);
}

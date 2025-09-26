import * as authController from '../controllers/authController.js';
import { validate } from '../middleware/validationMiddleware.js';
import { registerSchema, loginSchema, otpSchema } from '../validation/authValidation.js';

export default async function authRoutes(fastify) {
  fastify.post('/register', { preHandler: [validate(registerSchema)] }, authController.register);
  fastify.post('/verify-otp', { preHandler: [validate(otpSchema)] }, authController.verifyOTP);
  fastify.post('/login', { preHandler: [validate(loginSchema)] }, authController.login);
  fastify.post('/logout', authController.logout);
  fastify.post('/renew-token', authController.renewToken);
}

import { jest } from '@jest/globals';
import { PrismaClient } from '../generated/prisma/index.js';
import * as authController from '../controllers/authController.js';
import * as tokenService from '../services/tokenService.js';
import * as otpService from '../services/otpService.js';
import argon2 from 'argon2';

// Mock external dependencies
jest.mock('../generated/prisma/index.js', () => ({
  PrismaClient: jest.fn(() => ({
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    session: {
      create: jest.fn(),
      deleteMany: jest.fn(),
      findUnique: jest.fn(),
      findFirst: jest.fn(),
    },
  })),
}));
jest.mock('../services/tokenService.js');
jest.mock('../services/otpService.js');
jest.mock('argon2');

describe('authController', () => {
  let prisma;
  let req;
  let reply;
  let redis;

  beforeEach(() => {
    prisma = new PrismaClient();
    redis = {
      set: jest.fn(),
      get: jest.fn(),
      del: jest.fn(),
      incr: jest.fn(),
      expire: jest.fn(),
    };
    req = {
      body: {},
      cookies: {},
      ip: '127.0.0.1',
      headers: { 'user-agent': 'jest-test' },
      server: { redis },
    };
    reply = {
      status: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      setCookie: jest.fn().mockReturnThis(),
      clearCookie: jest.fn().mockReturnThis(),
    };

    // Reset mocks
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register a new user and send OTP', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      prisma.user.create.mockResolvedValue({ id: 'user123', email: 'test@example.com', verified: false });
      argon2.hash.mockResolvedValue('hashedPassword');
      otpService.sendOTPEmail.mockResolvedValue(true);

      req.body = { email: 'test@example.com', password: 'password123' };

      await authController.register(req, reply);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email: 'test@example.com' } });
      expect(argon2.hash).toHaveBeenCalledWith('password123');
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          email: 'test@example.com',
          passwordHash: 'hashedPassword',
          verified: false,
        },
      });
      expect(redis.set).toHaveBeenCalledWith(expect.stringContaining('otp:user123'), expect.any(String), { EX: 600 });
      expect(otpService.sendOTPEmail).toHaveBeenCalledWith('test@example.com', expect.any(String));
      expect(reply.send).toHaveBeenCalledWith({ message: 'User registered. OTP sent to email.' });
    });

    it('should return 400 if email is already in use', async () => {
      prisma.user.findUnique.mockResolvedValue({ id: 'user123', email: 'test@example.com' });
      req.body = { email: 'test@example.com', password: 'password123' };

      await authController.register(req, reply);

      expect(reply.status).toHaveBeenCalledWith(400);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Email already in use' });
    });
  });

  describe('verifyOTP', () => {
    it('should verify OTP and activate account', async () => {
      prisma.user.findUnique.mockResolvedValue({ id: 'user123', email: 'test@example.com', verified: false });
      redis.get.mockResolvedValue('hashedOtp');
      argon2.verify.mockResolvedValue(true);
      prisma.user.update.mockResolvedValue({ id: 'user123', email: 'test@example.com', verified: true });

      req.body = { email: 'test@example.com', otp: '123456' };

      await authController.verifyOTP(req, reply);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email: 'test@example.com' } });
      expect(redis.get).toHaveBeenCalledWith('otp:user123');
      expect(argon2.verify).toHaveBeenCalledWith('hashedOtp', '123456');
      expect(prisma.user.update).toHaveBeenCalledWith({ where: { email: 'test@example.com' }, data: { verified: true } });
      expect(redis.del).toHaveBeenCalledWith('otp:user123');
      expect(reply.send).toHaveBeenCalledWith({ message: 'OTP verified. Account activated.' });
    });

    it('should return 400 for invalid or expired OTP', async () => {
      prisma.user.findUnique.mockResolvedValue({ id: 'user123', email: 'test@example.com', verified: false });
      redis.get.mockResolvedValue('hashedOtp');
      argon2.verify.mockResolvedValue(false);

      req.body = { email: 'test@example.com', otp: 'wrongotp' };

      await authController.verifyOTP(req, reply);

      expect(reply.status).toHaveBeenCalledWith(400);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Invalid or expired OTP' });
    });
  });

  describe('login', () => {
    it('should log in a user and set cookies', async () => {
      const user = { id: 'user123', email: 'test@example.com', passwordHash: 'hashedPassword', verified: true, role: 'user' };
      prisma.user.findUnique.mockResolvedValue(user);
      argon2.verify.mockResolvedValue(true);
      tokenService.generateAccessToken.mockReturnValue('accessToken');
      tokenService.generateRefreshToken.mockReturnValue('refreshToken');
      redis.get.mockResolvedValue(0);
      redis.del.mockResolvedValue(1);
      prisma.session.create.mockResolvedValue({});
      redis.set.mockResolvedValue('OK');

      req.body = { email: 'test@example.com', password: 'password123' };

      await authController.login(req, reply);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { email: 'test@example.com' } });
      expect(argon2.verify).toHaveBeenCalledWith('hashedPassword', 'password123');
      expect(tokenService.generateAccessToken).toHaveBeenCalledWith({ userId: 'user123', role: 'user' });
      expect(tokenService.generateRefreshToken).toHaveBeenCalledWith({ userId: 'user123' });
      expect(prisma.session.create).toHaveBeenCalled();
      expect(redis.set).toHaveBeenCalledWith(
        'session:user123',
        JSON.stringify({ ip: '127.0.0.1', userAgent: 'jest-test', refreshToken: 'refreshToken' }),
        { EX: 3600 }
      );
      expect(redis.del).toHaveBeenCalledWith('login:fail:test@example.com');
      expect(reply.setCookie).toHaveBeenCalledTimes(2);
      expect(reply.send).toHaveBeenCalledWith({ message: 'Logged in successfully' });
    });

    it('should return 401 for invalid credentials', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      redis.get.mockResolvedValue(0);
      redis.incr.mockResolvedValue(1);
      redis.expire.mockResolvedValue(1);

      req.body = { email: 'test@example.com', password: 'wrongpassword' };

      await authController.login(req, reply);

      expect(redis.incr).toHaveBeenCalledWith('login:fail:test@example.com');
      expect(redis.expire).toHaveBeenCalledWith('login:fail:test@example.com', 900);
      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Invalid credentials' });
    });

    it('should return 403 if account is not verified', async () => {
      const user = { id: 'user123', email: 'test@example.com', passwordHash: 'hashedPassword', verified: false };
      prisma.user.findUnique.mockResolvedValue(user);
      argon2.verify.mockResolvedValue(true);
      redis.get.mockResolvedValue(0);

      req.body = { email: 'test@example.com', password: 'password123' };

      await authController.login(req, reply);

      expect(reply.status).toHaveBeenCalledWith(403);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Account not verified. Check your email.' });
    });

    it('should return 429 for too many failed attempts', async () => {
      redis.get.mockResolvedValue(5);

      req.body = { email: 'test@example.com', password: 'password123' };

      await authController.login(req, reply);

      expect(reply.status).toHaveBeenCalledWith(429);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Too many failed attempts. Try again later.' });
    });
  });

  describe('logout', () => {
    it('should clear cookies and delete session', async () => {
      req.cookies.refreshToken = 'someRefreshToken';
      prisma.session.deleteMany.mockResolvedValue({ count: 1 });
      prisma.session.findFirst.mockResolvedValue({ userId: 'user123' });
      redis.del.mockResolvedValue(1);

      await authController.logout(req, reply);

      expect(prisma.session.deleteMany).toHaveBeenCalledWith({ where: { refreshToken: 'someRefreshToken' } });
      expect(prisma.session.findFirst).toHaveBeenCalledWith({
        where: { refreshToken: 'someRefreshToken' },
        select: { userId: true },
      });
      expect(redis.del).toHaveBeenCalledWith('session:user123');
      expect(reply.clearCookie).toHaveBeenCalledTimes(2);
      expect(reply.send).toHaveBeenCalledWith({ message: 'Logged out successfully' });
    });

    it('should do nothing if no refresh token is present', async () => {
      req.cookies.refreshToken = undefined;

      await authController.logout(req, reply);

      expect(prisma.session.deleteMany).not.toHaveBeenCalled();
      expect(redis.del).not.toHaveBeenCalled();
      expect(reply.clearCookie).toHaveBeenCalledTimes(2);
      expect(reply.send).toHaveBeenCalledWith({ message: 'Logged out successfully' });
    });
  });

  describe('renewToken', () => {
    it('should renew access token', async () => {
      req.cookies.refreshToken = 'validRefreshToken';
      tokenService.verifyRefreshToken.mockReturnValue({ userId: 'user123', role: 'user' });
      prisma.session.findUnique.mockResolvedValue({ refreshToken: 'validRefreshToken', expiresAt: new Date(Date.now() + 100000) });
      tokenService.generateAccessToken.mockReturnValue('newAccessToken');
      redis.get.mockResolvedValue(JSON.stringify({ ip: '127.0.0.1', userAgent: 'jest-test', refreshToken: 'validRefreshToken' }));
      redis.set.mockResolvedValue('OK');

      await authController.renewToken(req, reply);

      expect(tokenService.verifyRefreshToken).toHaveBeenCalledWith('validRefreshToken');
      expect(prisma.session.findUnique).toHaveBeenCalledWith({ where: { refreshToken: 'validRefreshToken' } });
      expect(tokenService.generateAccessToken).toHaveBeenCalledWith({ userId: 'user123', role: 'user' });
      expect(redis.get).toHaveBeenCalledWith('session:user123');
      expect(redis.set).toHaveBeenCalledWith(
        'session:user123',
        expect.stringContaining('newAccessToken'), // The actual token is not in the redis session, but the lastAccess is updated
        { EX: 3600 }
      );
      expect(reply.setCookie).toHaveBeenCalledWith(
        'accessToken',
        'newAccessToken',
        expect.any(Object)
      );
      expect(reply.send).toHaveBeenCalledWith({ message: 'Access token renewed' });
    });

    it('should return 401 for expired or invalid session', async () => {
      req.cookies.refreshToken = 'invalidRefreshToken';
      tokenService.verifyRefreshToken.mockReturnValue({ userId: 'user123', role: 'user' });
      prisma.session.findUnique.mockResolvedValue(null);

      await authController.renewToken(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Session expired or invalid' });
    });

    it('should return 401 for invalid refresh token', async () => {
      req.cookies.refreshToken = 'invalidRefreshToken';
      tokenService.verifyRefreshToken.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await authController.renewToken(req, reply);

      expect(reply.status).toHaveBeenCalledWith(401);
      expect(reply.send).toHaveBeenCalledWith({ error: 'Invalid refresh token' });
    });
  });
});

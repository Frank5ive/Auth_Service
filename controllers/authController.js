import argon2 from 'argon2';
import { PrismaClient } from '../generated/prisma/index.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from '../services/tokenService.js';
import { sendOTPEmail } from '../services/otpService.js';
import { BadRequestError, UnauthorizedError, ForbiddenError, TooManyRequestsError } from '../utils/errors.js';

const prisma = new PrismaClient();

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// --- Register ---
export const register = async (req, reply) => {
  const { email, password } = req.body;

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) throw new BadRequestError('Email already in use', 'EMAIL_IN_USE');

  const hashedPassword = await argon2.hash(password);
  const otp = generateOTP();
  const hashedOtp = await argon2.hash(otp);

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash: hashedPassword,
      verified: false,
    },
  });

  // ✅ Store OTP in Redis
  await req.server.redis.set(`otp:${user.id}`, hashedOtp, { EX: 600 }); // 10 minutes

  await sendOTPEmail(email, otp);

  reply.send({ message: 'User registered. OTP sent to email.' });
};

// --- Verify OTP ---
export const verifyOTP = async (req, reply) => {
  const { email, otp } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.verified) throw new BadRequestError('User not found or already verified', 'USER_NOT_FOUND_OR_VERIFIED');

  // ✅ Fetch OTP from Redis
  const storedOtp = await req.server.redis.get(`otp:${user.id}`);
  if (!storedOtp || !(await argon2.verify(storedOtp, otp))) {
    throw new BadRequestError('Invalid or expired OTP', 'INVALID_OR_EXPIRED_OTP');
  }

  await prisma.user.update({ where: { email }, data: { verified: true } });
  await req.server.redis.del(`otp:${user.id}`);

  reply.send({ message: 'OTP verified. Account activated.' });
};

// --- Login ---
export const login = async (req, reply) => {
  const { email, password } = req.body;
  const redis = req.server.redis;

  const user = await prisma.user.findUnique({ where: { email } });
  const ip = req.ip;
  const agent = req.headers['user-agent'] || 'unknown';

  // ✅ Brute force protection (email/IP combo)
  const failKey = `login:fail:${email}`;
  const fails = parseInt(await redis.get(failKey)) || 0;

  if (fails >= 5) {
    throw new TooManyRequestsError('Too many failed attempts. Try again later.', 'TOO_MANY_LOGIN_ATTEMPTS');
  }

  if (!user || !(await argon2.verify(user.passwordHash, password))) {
    await redis.incr(failKey);
    await redis.expire(failKey, 900); // 15 min lock
    throw new UnauthorizedError('Invalid credentials', 'INVALID_CREDENTIALS');
  }

  if (!user.verified) {
    throw new ForbiddenError('Account not verified. Check your email.', 'ACCOUNT_NOT_VERIFIED');
  }

  const accessToken = generateAccessToken({ userId: user.id, role: user.role });
  const refreshToken = generateRefreshToken({ userId: user.id });

  // ✅ Save session in DB
  await prisma.session.create({
    data: {
      userId: user.id,
      ip,
      userAgent: agent,
      refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  // ✅ Save session in Redis
  await redis.set(`session:${user.id}`, JSON.stringify({
    ip, userAgent: agent, refreshToken,
  }), { EX: 3600 }); // 1 hour

  // ✅ Reset brute-force counter
  await redis.del(failKey);

  reply
    .setCookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 15 * 60,
    })
    .setCookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60,
    })
    .send({ message: 'Logged in successfully' });
};

// --- Logout ---
export const logout = async (req, reply) => {
  const { refreshToken } = req.cookies;
  const redis = req.server.redis;

  if (refreshToken) {
    await prisma.session.deleteMany({ where: { refreshToken } });

    try {
      const userId = (await prisma.session.findFirst({
        where: { refreshToken },
        select: { userId: true },
      }))?.userId;

      if (userId) await redis.del(`session:${userId}`);
    } catch {}
  }

  reply
    .clearCookie('accessToken', { path: '/' })
    .clearCookie('refreshToken', { path: '/' })
    .send({ message: 'Logged out successfully' });
};

// --- Renew Token ---
export const renewToken = async (req, reply) => {
  const { refreshToken } = req.cookies;
  const redis = req.server.redis;

  try {
    const decoded = verifyRefreshToken(refreshToken);

    const session = await prisma.session.findUnique({
      where: { refreshToken },
    });

    if (!session || session.expiresAt < new Date()) {
      throw new UnauthorizedError('Session expired or invalid', 'SESSION_EXPIRED_OR_INVALID');
    }

    const newAccessToken = generateAccessToken({
      userId: decoded.userId,
      role: decoded.role,
    });

    // ✅ Also update Redis session if exists
    const redisSession = await redis.get(`session:${decoded.userId}`);
    if (redisSession) {
      const parsed = JSON.parse(redisSession);
      parsed.lastAccess = Date.now();
      await redis.set(`session:${decoded.userId}`, JSON.stringify(parsed), { EX: 3600 });
    }

    reply.setCookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 15 * 60,
    });

    reply.send({ message: 'Access token renewed' });
  } catch (err) {
    throw new UnauthorizedError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
  }
};

import argon2 from 'argon2';
import { PrismaClient } from '../generated/prisma/index.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from '../services/tokenService.js';
import { sendOTPEmail } from '../services/otpService.js';

const prisma = new PrismaClient();

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// --- Register ---
export const register = async (req, reply) => {
  const { email, password } = req.body;

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) return reply.status(400).send({ error: 'Email already in use' });

  const hashedPassword = await argon2.hash(password);
  const otp = generateOTP();

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash: hashedPassword,
      verified: false,
    },
  });

  // ✅ Store OTP in Redis
  await req.server.redis.set(`otp:${user.id}`, otp, { EX: 600 }); // 10 minutes

  await sendOTPEmail(email, otp);

  reply.send({ message: 'User registered. OTP sent to email.' });
};

// --- Verify OTP ---
export const verifyOTP = async (req, reply) => {
  const { email, otp } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.verified) return reply.status(400).send({ error: 'User not found or already verified' });

  // ✅ Fetch OTP from Redis
  const storedOtp = await req.server.redis.get(`otp:${user.id}`);
  if (!storedOtp || storedOtp !== otp) {
    return reply.status(400).send({ error: 'Invalid or expired OTP' });
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
    return reply.status(429).send({ error: 'Too many failed attempts. Try again later.' });
  }

  if (!user || !(await argon2.verify(user.passwordHash, password))) {
    await redis.incr(failKey);
    await redis.expire(failKey, 900); // 15 min lock
    return reply.status(401).send({ error: 'Invalid credentials' });
  }

  if (!user.verified) {
    return reply.status(403).send({ error: 'Account not verified. Check your email.' });
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
      return reply.status(401).send({ error: 'Session expired or invalid' });
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
    reply.status(401).send({ error: 'Invalid refresh token' });
  }
};

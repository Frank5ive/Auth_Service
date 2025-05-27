import argon2 from 'argon2';
import { PrismaClient } from '../generated/prisma/index.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from '../services/tokenService.js';
import { sendOTPEmail } from '../services/otpService.js';

const prisma = new PrismaClient();

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// --- Register User ---
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

  await prisma.oTPToken.create({
    data: {
      userId: user.id,
      code: otp,
      type: 'verify',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    },
  });

  await sendOTPEmail(email, otp);

  reply.send({ message: 'User registered. OTP sent to email.' });
};

// --- Verify OTP ---
export const verifyOTP = async (req, reply) => {
  const { email, otp } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.verified) {
    return reply.status(400).send({ error: 'User not found or already verified' });
  }

  const otpToken = await prisma.oTPToken.findFirst({
    where: {
      userId: user.id,
      code: otp,
      type: 'verify',
      expiresAt: { gt: new Date() },
    },
  });

  if (!otpToken) {
    return reply.status(400).send({ error: 'Invalid or expired OTP' });
  }

  await prisma.user.update({
    where: { email },
    data: {
      verified: true,
    },
  });

  await prisma.oTPToken.delete({ where: { id: otpToken.id } });

  reply.send({ message: 'OTP verified. Account activated.' });
};

// --- Login ---
export const login = async (req, reply) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await argon2.verify(user.passwordHash, password)))
    return reply.status(401).send({ error: 'Invalid credentials' });

  if (!user.verified)
    return reply.status(403).send({ error: 'Account not verified. Check your email for OTP.' });

  const accessToken = generateAccessToken({ userId: user.id, role: user.role });
  const refreshToken = generateRefreshToken({ userId: user.id });

  await prisma.session.create({
    data: {
      userId: user.id,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || 'Unknown',
      refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
  });

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

  if (refreshToken) {
    await prisma.session.deleteMany({ where: { refreshToken } });
  }

  reply
    .clearCookie('accessToken', { path: '/' })
    .clearCookie('refreshToken', { path: '/' })
    .send({ message: 'Logged out successfully' });
};

// --- Renew Access Token ---
export const renewToken = async (req, reply) => {
  const { refreshToken } = req.cookies;

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

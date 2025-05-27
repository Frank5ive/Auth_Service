import { verifyAccessToken } from '../services/tokenService.js';

export default async function (req, reply) {
  try {
    const token = req.cookies.accessToken;
    if (!token) throw new Error('No access token');

    const decoded = verifyAccessToken(token);
    req.user = decoded;
  } catch (err) {
    // Do nothing — auto-renew will be handled by route or frontend retry
  }
}

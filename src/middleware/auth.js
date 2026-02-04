import { verifyAccessToken,rotateTokens } from '../utils/token';

export async function authMiddleware(req, res, next) {
  try {
    const accessToken = req.cookies['accessToken'];
    const refreshToken = req.cookies['refreshToken'];

    // no tokens → unauthenticated
    if (!accessToken && !refreshToken) {
      req.user = null;
      return next();
    }

    // Try verifying access token
    const decoded = verifyAccessToken(accessToken);
    if (decoded) {
      req.user = decoded;
      return next();
    }

    // access token invalid / expired → try refresh
    if (refreshToken) {
      const rotated = await rotateTokens(refreshToken); // returns { accessToken, refreshToken, user }
      if (!rotated) {
        req.user = null;
        return next();
      }

      // set new tokens in cookies
      res.cookie('accessToken', rotated.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });
      res.cookie('refreshToken', rotated.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });

      req.user = rotated.user;
      return next();
    }

    // if we reach here → not authenticated
    req.user = null;
    next();
  } catch (err) {
    console.error('Auth middleware error', err);
    req.user = null;
    next();
  }
}

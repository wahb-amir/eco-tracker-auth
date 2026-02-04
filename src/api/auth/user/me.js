// routes/user.ts
import { Router, Request, Response } from 'express';
import { authMiddleware } from '../middleware/auth';

const router = Router();

router.get('/me', authMiddleware, (req, res) => {
  const user = req.user;

  if (!user) {
    return res.status(200).json(null);
  }

  // return only minimal info
  return res.status(200).json({
    id: user.id,
    email: user.email,
    role: user.role,
  });
});

export default router;

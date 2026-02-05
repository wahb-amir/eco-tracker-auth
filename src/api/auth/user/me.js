// routes/user.ts
import { Router } from 'express';
import authMiddleware from '../../../middleware/auth.js';
const router = Router();

router.get('/me', authMiddleware, (req, res) => {
  const user = req.user;
  if (!user) {
    return res.status(200).json(null);
  }
  return res.status(200).json({
    id: user?.uid
  });
});

export default router;

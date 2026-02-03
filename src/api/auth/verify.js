// src/api/auth/verify.js
import express from "express";
import jwt from "jsonwebtoken";
import User from "../../model/User.js";

const router = express.Router();

router.get("/", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ msg: "Token is required" });

  const publicKey = process.env.PUBLIC_KEY;
  if (!publicKey) {
    console.error("PUBLIC_KEY is not set in env");
    return res.status(500).json({ msg: "Server misconfiguration" });
  }

  let payload;
  try {
    // Verify signature and expiry
    payload = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
  } catch (err) {
    // If token expired, try to clear any stored token so it can't be reused
    if (err.name === "TokenExpiredError") {
      try {
        const userToCleanup = await User.findOne({ "verificationToken.token": token });
        if (userToCleanup) {
          userToCleanup.verificationToken = { token: null, createdAt: null };
          await userToCleanup.save();
        }
      } catch (cleanupErr) {
        console.error("Error cleaning up expired verification token:", cleanupErr);
      }
      return res.status(410).json({ msg: "Verification token has expired" });
    }

    // Other verification errors
    console.error("Token verification error:", err);
    return res.status(400).json({ msg: "Invalid verification token" });
  }

  try {
    // payload should contain id (from your generator)
    const userId = payload.id || payload._id;
    if (!userId) return res.status(400).json({ msg: "Token payload missing user id" });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ msg: "User not found" });

    if (user.verified) {
      return res.status(400).json({ msg: "User already verified" });
    }

    // Ensure the stored token matches (defense-in-depth)
    if (!user.verificationToken?.token || user.verificationToken.token !== token) {
      return res.status(400).json({ msg: "Token does not match our records" });
    }

    // Mark verified (use schema method if available)
    if (typeof user.markVerified === "function") {
      user.markVerified();
    } else {
      user.verified = true;
      user.verificationToken = { token: null, createdAt: null };
    }

    await user.save();

    // Success — you can redirect to a frontend page instead of returning JSON
    return res.status(200).json({ msg: "Account verified successfully" });
  } catch (e) {
    console.error("Error in verify route:", e);
    return res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router;

// src/api/auth/verify.js
import express from "express";
import User from "../../../model/User.js";
import { verifyVerificationToken, hashOtp, generateAccessToken, generateRefreshToken } from "../../../utils/token.js";

const router = express.Router();

/**
 * GET /info
 * Returns the email associated with the verificationToken cookie
 */
router.get("/info", async (req, res) => {
  try {
    const token = req.cookies?.verificationToken;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    let decoded;
    try {
      decoded = verifyVerificationToken(token);
    } catch {
      return res.status(401).json({ error: "Invalid or expired verification token" });
    }

    if (!decoded?.uid) return res.status(401).json({ error: "Invalid token" });

    const user = await User.findById(decoded.uid);
    if (!user) return res.status(404).json({ error: "User not found" });

    return res.status(200).json({ email: user.email });
  } catch (e) {
    console.error("error in verify get:", e);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

/**
 * POST /
 * Verify OTP sent to email and return access + refresh tokens
 */
router.post("/", async (req, res) => {
  try {
    const { otp, email: emailFromBody } = req.body;

    if (!otp || typeof otp !== "string" || !/^\d{6}$/.test(otp.trim())) {
      return res.status(400).json({ error: "OTP is required and must be a 6-digit string" });
    }
    const otpValue = otp.trim();

    let user = null;
    const token = req.cookies?.verificationToken;

    // try to get user from token
    if (token) {
      try {
        const decoded = verifyVerificationToken(token);
        if (!decoded?.uid) return res.status(401).json({ error: "Invalid verification token" });
        user = await User.findById(decoded.uid);
      } catch {
        return res.status(401).json({ error: "Invalid or expired verification token" });
      }
    } 
    // fallback: get user from email
    else if (emailFromBody && typeof emailFromBody === "string") {
      user = await User.findOne({ email: emailFromBody.toLowerCase().trim() });
    } else {
      return res.status(401).json({ error: "No verification token or email provided" });
    }

    if (!user) return res.status(404).json({ error: "User not found" });

    // OTP not set
    if (!user.verificationOtp || !user.verificationOtp.codeHash) {
      return res.status(400).json({ error: "OTP not set" });
    }

    const now = new Date();
    if (user.verificationOtp.expiresAt && now > user.verificationOtp.expiresAt) {
      return res.status(410).json({ error: "OTP expired" });
    }

    // Compare OTP
    const otpHash = hashOtp(otpValue);
    if (otpHash !== user.verificationOtp.codeHash) {
      return res.status(401).json({ error: "Incorrect OTP" });
    }

    // Mark user verified & clear OTP
    user.verified = true;
    user.verificationOtp = null;
    await user.save();

    // Clear verification cookie
    res.clearCookie("verificationToken", { httpOnly: true, path: "/" });

    // Generate access & refresh tokens
    const accessToken = generateAccessToken({ uid: user._id.toString(), email: user.email });
    const refreshToken = generateRefreshToken({ uid: user._id.toString(), email: user.email });

    return res.json({ message: "Verified successfully", accessToken, refreshToken });
  } catch (e) {
    console.error("error in verify post", e);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;

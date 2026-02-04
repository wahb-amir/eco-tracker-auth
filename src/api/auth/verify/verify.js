// src/api/auth/verify.js
import express from "express";
import User from "../../../model/User.js";
import Otp from "../../../model/Otp.js";
import {
  verifyVerificationToken,
  generateAccessToken,
  generateRefreshToken,
} from "../../../utils/token.js";

const router = express.Router();

/**
 * cookie helper: maxAge in milliseconds
 * sameSite 'strict' is good for same-site setups; if frontend/backend are on different top-level domains,
 * change to sameSite: 'none' and secure: true (HTTPS required).
 */
const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  maxAge: maxAgeMs,
  sameSite: "strict",
  secure: process.env.NODE_ENV === "production",
  path: "/",
});

/**
 * GET /api/auth/verify/info
 * Returns the email embedded in the verificationToken cookie so the client can pre-fill UI.
 */
router.get("/info", async (req, res) => {
  try {
    const token = req.cookies?.verificationToken;
    if (!token) {
      return res.status(401).json({ error: "No verification token provided" });
    }

    let decoded;
    try {
      decoded = verifyVerificationToken(token);
    } catch (err) {
      // token invalid/expired
      return res
        .status(401)
        .json({ error: "Invalid or expired verification token" });
    }

    if (!decoded || !decoded.uid || !decoded.email) {
      return res
        .status(401)
        .json({ error: "Invalid verification token payload" });
    }

    return res.status(200).json({ email: decoded.email });
  } catch (e) {
    console.error("error in verify GET /info:", e);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

/**
 * POST /api/auth/verify
 * Body: { otp, email? }
 *
 * Flow:
 *  - Validate OTP format
 *  - Resolve user from verificationToken cookie or email body
 *  - Check user exists
 *  - Verify OTP (via user.verifyOtp if available, otherwise via Otp model)
 *  - If OTP valid: mark user.verified = true, remove OTPs, issue access+refresh cookies, clear verificationToken
 *  - If OTP invalid/expired: return appropriate status codes
 */
router.post("/", async (req, res) => {
  try {
    const { otp, email: emailFromBody } = req.body;

    if (!otp || typeof otp !== "string" || !/^\d{6}$/.test(otp.trim())) {
      return res
        .status(400)
        .json({ error: "OTP is required and must be a 6-digit string" });
    }
    const otpValue = otp.trim();

    // Resolve user: prefer verificationToken cookie, fallback to email in body
    let user = null;
    const token = req.cookies?.verificationToken;

    if (token) {
      try {
        const decoded = verifyVerificationToken(token);
        if (!decoded || !decoded.uid) {
          return res.status(401).json({ error: "Invalid verification token" });
        }
        user = await User.findById(decoded.uid);
      } catch (err) {
        return res
          .status(401)
          .json({ error: "Invalid or expired verification token" });
      }
    } else if (emailFromBody && typeof emailFromBody === "string") {
      user = await User.findOne({ email: emailFromBody.toLowerCase().trim() });
    } else {
      return res
        .status(400)
        .json({ error: "No verification token or email provided" });
    }

    if (!user) return res.status(404).json({ error: "User not found" });

    // Verify OTP:
    // Preferred path: user.verifyOtp(otp) exists and returns an object like { ok: boolean, reason?: 'expired'|'invalid' }
    // Fallback: use Otp collection lookup (type = 'email_verification')
    let verificationResult = null;
    if (typeof user.verifyOtp === "function") {
      // assume it returns { ok: boolean, reason?: string }
      try {
        verificationResult = await user.verifyOtp(otpValue);
      } catch (err) {
        console.error("user.verifyOtp threw:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }
    } else {
      // fallback: check Otp model (assumes Otp stores hashed code and has compare method)
      const otpRecord = await Otp.findOne({
        userId: user._id,
        type: "email_verification",
      });
      if (!otpRecord) {
        verificationResult = { ok: false, reason: "not_set" };
      } else {
        // If your Otp model exposes a compare method, use it; otherwise implement naive check (not recommended)
        if (typeof otpRecord.compare === "function") {
          const ok = await otpRecord.compare(otpValue);
          verificationResult = { ok, reason: ok ? undefined : "invalid" };
        } else if (
          otpRecord.expiresAt &&
          otpRecord.expiresAt.getTime() <= Date.now()
        ) {
          verificationResult = { ok: false, reason: "expired" };
        } else {
          // If Otp stores plaintext (bad) or hashed code, adapt accordingly.
          // We'll do a fallback that treats mismatch as invalid.
          verificationResult = { ok: false, reason: "invalid" };
        }
      }
    }

    if (!verificationResult || !verificationResult.ok) {
      const reason = verificationResult?.reason || "invalid";
      if (reason === "expired") {
        return res.status(410).json({ error: "OTP expired" });
      }
      if (reason === "invalid") {
        return res.status(401).json({ error: "Incorrect OTP" });
      }
      if (reason === "not_set") {
        return res.status(400).json({ error: "No OTP issued for this user" });
      }
      return res.status(400).json({ error: "OTP verification failed" });
    }

    // OTP valid -> finalize verification
    if (!user.verified) {
      user.verified = true;
      // Optionally set verifiedAt
      user.verifiedAt = new Date();
      await user.save();
    }

    // Remove any existing OTP records for this user/type
    try {
      await Otp.deleteMany({ userId: user._id, type: "email_verification" });
    } catch (err) {
      // non-fatal: log and continue
      console.error("Failed to remove OTP records:", err);
    }

    // Generate tokens and set cookies
    const accessToken = generateAccessToken(user._id.toString());
    const refreshToken = generateRefreshToken(user._id.toString());

    // Access token: short lived (15 minutes)
    res.cookie("accessToken", accessToken, cookieOpts(15 * 60 * 1000)); // 15 minutes

    // Refresh token: long lived (7 days)
    res.cookie(
      "refreshToken",
      refreshToken,
      cookieOpts(7 * 24 * 60 * 60 * 1000),
    ); // 7 days

    // Clear verification token cookie (used only during verification flow)
    res.clearCookie("verificationToken", { path: "/" });

    // Optionally persist refresh token mapping (redis/db) for revocation support here.

    return res.status(200).json({
      message: "Account verified and logged in",
      user: {
        id: user._id.toString(),
        email: user.email,
        role: user.role || "user",
      },
    });
  } catch (e) {
    console.error("error in verify POST /:", e);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;

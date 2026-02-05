// src/api/auth/verify.js
import express from "express";
import User from "../../../model/User.js";
import Otp, { hashOtp } from "../../../model/Otp.js";
import {
  verifyVerificationToken,
  generateAccessToken,
  generateRefreshToken,
} from "../../../utils/token.js";

const router = express.Router();

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
 * Manual OTP verification (no schema helpers).
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

    // -------- Manual OTP verification logic (no schema helpers) --------
    const MAX_ATTEMPTS = 10;
    const otpRecord = await Otp.findOne({
      userId: user._id,
      type: "email_verification",
    });

    let verificationOk = false;
    let reason = "invalid";

    if (!otpRecord) {
      reason = "not_set";
    } else {
      // check expiry explicitly
      if (otpRecord.expiresAt && otpRecord.expiresAt.getTime() <= Date.now()) {
        // delete expired record (one-time)
        try {
          await Otp.deleteOne({ _id: otpRecord._id });
        } catch (err) {
          console.error("Failed to delete expired OTP record:", err);
        }
        reason = "expired";
      } else if (otpRecord.attempts >= MAX_ATTEMPTS) {
        // too many attempts — remove record to require fresh OTP
        try {
          await Otp.deleteOne({ _id: otpRecord._id });
        } catch (err) {
          console.error("Failed to delete OTP after too many attempts:", err);
        }
        reason = "too_many_attempts";
      } else {
        // compare hash
        try {
          const candidateHash = hashOtp(otpValue);
          if (candidateHash === otpRecord.codeHash) {
            // success: delete the OTP record (one-time use)
            try {
              await Otp.deleteOne({ _id: otpRecord._id });
            } catch (err) {
              console.error("Failed to delete OTP record after success:", err);
            }
            verificationOk = true;
            reason = undefined;
          } else {
            // incorrect: increment attempts
            try {
              await Otp.updateOne(
                { _id: otpRecord._id },
                { $inc: { attempts: 1 } },
              );
            } catch (err) {
              console.error("Failed to increment OTP attempts:", err);
            }
            reason = "invalid";
          }
        } catch (err) {
          console.error("Error while comparing OTP hashes:", err);
          return res.status(500).json({ error: "Internal Server Error" });
        }
      }
    }

    // Map reasons -> HTTP status
    if (!verificationOk) {
      if (reason === "expired") {
        return res.status(410).json({ error: "OTP expired" });
      }
      if (reason === "invalid") {
        return res.status(401).json({ error: "Incorrect OTP" });
      }
      if (reason === "not_set") {
        return res.status(400).json({ error: "No OTP issued for this user" });
      }
      if (reason === "too_many_attempts") {
        return res
          .status(429)
          .json({ error: "Too many attempts. A new OTP is required." });
      }
      return res.status(400).json({ error: "OTP verification failed" });
    }

    // OTP valid -> finalize verification
    if (!user.verified) {
      user.verified = true;
      user.verifiedAt = new Date();
      await user.save();
    }

    // Ensure any existing OTP records for this user/type are removed (best-effort)
    try {
      await Otp.deleteMany({ userId: user._id, type: "email_verification" });
    } catch (err) {
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

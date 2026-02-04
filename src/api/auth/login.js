import express from "express";
import User from "../../model/User.js";
import Otp from "../../model/Otp.js";
import {
  generateVerificationToken,
  generateAccessToken,
  generateRefreshToken,
} from "../../utils/token.js";
import { sendOtpEmail } from "../../utils/mailer.js";
import { comparePassword } from "../../utils/hashPassword.js";

const router = express.Router();

// cookie helper: maxAge in milliseconds
const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  maxAge: maxAgeMs,
  sameSite: "strict", // adjust to 'none' + secure for cross-site scenarios
  secure: process.env.NODE_ENV === "production",
  path: "/",
});

/**
 * POST /api/auth
 * login endpoint
 *
 * Body: { email, password }
 *
 * Behavior:
 * - If user not found / wrong password => 401
 * - If user exists but not verified:
 *     - if an unexpired OTP exists -> do NOT resend, set verificationToken cookie, return redirectTo
 *     - if no OTP or expired -> create+send new OTP, set verificationToken cookie, return redirectTo
 * - If user verified:
 *     - generate access + refresh tokens, set cookies, return minimal user payload
 */
router.post("/", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Missing email or password" });
    }

    const emailLower = String(email).trim().toLowerCase();

    // fetch user as mongoose document (not lean) so we can update if needed later
    const user = await User.findOne({ email: emailLower });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // verify password
    const passwordMatches = await comparePassword(password, user.password);
    if (!passwordMatches)
      return res.status(401).json({ message: "Invalid credentials" });

    // If user not verified => ensure OTP exists (or create), set verification cookie, return redirectTo
    if (!user.verified) {
      const otpType = "email_verification";

      // find current OTP record (if any)
      let otpRecord = await Otp.findOne({ userId: user._id, type: otpType });

      const now = Date.now();
      let otpExistsAndValid = false;
      let newOtpPlain = null;

      if (otpRecord && otpRecord.expiresAt && otpRecord.expiresAt.getTime() > now) {
        otpExistsAndValid = true;
      } else {
        // create a fresh OTP record (this should save hashed code + expiresAt inside the model)
        // We assume Otp.createForUser returns the plaintext code for emailing
        newOtpPlain = await Otp.createForUser(user._id, otpType);
        try {
          // send email, but don't fail login if mail fails — show resend UI on client instead
          await sendOtpEmail(user.email, newOtpPlain, { expiryMinutes: 60 });
        } catch (mailErr) {
          console.error("Failed to send OTP email:", mailErr);
        }

        // reload the OTP record after creation so we can return its expiresAt
        otpRecord = await Otp.findOne({ userId: user._id, type: otpType });
      }

      // generate verification token (short-lived) and set as httpOnly cookie
      const verificationToken = generateVerificationToken({
        uid: user._id.toString(),
        email: user.email,
        type: "verification",
      });

      // 1 hour expiry for verification flow
      res.cookie("verificationToken", verificationToken, cookieOpts(60 * 60 * 1000));

      // Return redirect payload for client to navigate to /verify
      return res.status(200).json({
        redirectTo: "/verify",
        otpExists: otpExistsAndValid,
        otpExpiresAt: otpRecord?.expiresAt ? otpRecord.expiresAt.toISOString() : null,
        message: otpExistsAndValid
          ? "Verification OTP already issued"
          : "New verification OTP issued",
      });
    }

    // -----------------------
    // USER IS VERIFIED: issue access+refresh tokens and set cookies
    // -----------------------
    const accessToken = generateAccessToken(user._id.toString());
    const refreshToken = generateRefreshToken(user._id.toString());

    // Access token: short lived
    res.cookie("accessToken", accessToken, cookieOpts(15 * 60 * 1000)); // 15 minutes

    // Refresh token: long lived
    res.cookie("refreshToken", refreshToken, cookieOpts(7 * 24 * 60 * 60 * 1000)); // 7 days

    // Minimal user payload returned to client
    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id.toString(),
        email: user.email,
        role: user.role || "user",
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return next(err);
  }
});

export default router;

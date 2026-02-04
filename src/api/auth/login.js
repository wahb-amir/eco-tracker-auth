// routes/auth.js
import express from "express";
import User from "../../model/User.js";
import Otp from "../../model/Otp.js";
import { generateVerificationToken } from "../../utils/token.js";
import { sendOtpEmail } from "../../utils/mailer.js";
import { comparePassword } from "../../utils/hashPassword.js";

const router = express.Router();
const ONE_HOUR_MS = 1000 * 60 * 60;

const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  maxAge: maxAgeMs,
  sameSite: "strict",
  secure: process.env.NODE_ENV === "production",
  path: "/",
});

router.post("/", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Missing email or password" });
    }

    const emailLower = String(email).trim().toLowerCase();

    // fetch user as a mongoose document (not .lean()) so we can update if needed
    const user = await User.findOne({ email: emailLower });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // compare password (user.password expected to be bcrypt hash)
    const passwordMatches = await comparePassword(password, user.password);
    if (!passwordMatches) return res.status(401).json({ message: "Invalid credentials" });

    // If user not verified => ensure OTP exists and send (if needed), then redirect to /verify
    if (!user.verified) {
      const otpType = "email_verification";

      // find current OTP record (if any)
      const otpRecord = await Otp.findOne({ userId: user._id, type: otpType });

      let shouldCreateAndSend = true;

      if (otpRecord) {
        // if expiresAt exists and is still in the future -> keep it (don't spam)
        if (otpRecord.expiresAt && otpRecord.expiresAt.getTime() > Date.now()) {
          shouldCreateAndSend = false;
        } else {
          // expired (or no expiresAt) -> we will create a new one
          shouldCreateAndSend = true;
        }
      }

      if (shouldCreateAndSend) {
        // create (or replace) OTP and return plaintext to send
        const otpPlain = await Otp.createForUser(user._id, otpType);
        try {
          await sendOtpEmail(user.email, otpPlain, { expiryMinutes: 60 });
        } catch (mailErr) {
          console.error("Failed to send OTP email:", mailErr);
          // We still proceed to set verification cookie so user can trigger resend from /verify
          // (Alternatively you could return 500 here — choose what suits your UX.)
        }
      }

      // generate verification token (sent as httpOnly cookie)
      const verificationToken = generateVerificationToken({
        uid: user._id.toString(),
        email: user.email,
      });

      res.cookie("verificationToken", verificationToken, cookieOpts(60 * 60 * 1000)); // 1 hour
      return res.status(200).json({ redirectTo: "/verify", message: "Verification required" });
    }

    // User is verified -> issue session token and return success
    const sessionToken = generateVerificationToken({
      uid: user._id.toString(),
      email: user.email,
      type: "session",
    });

    // session cookie: 7 days
    res.cookie("sessionToken", sessionToken, cookieOpts(7 * 24 * 60 * 60 * 1000));
    return res.status(200).json({ message: "Login successful" });
  } catch (err) {
    console.error("Login error:", err);
    return next(err);
  }
});

export default router;

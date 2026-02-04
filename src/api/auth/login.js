// routes/auth.js
import express from "express";
import User from '../../model/User.js'
import bcrypt from "bcryptjs";
import { setUserOtp, generateVerificationToken } from "../../utils/token.js";
import { sendOtpEmail } from "../../utils/mailer.js";

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

    const user = await User.findOne({ email: email.toLowerCase() }).lean();
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // re-fetch writable document for updates
    const userDoc = await User.findById(user._id);
    if (!userDoc) return res.status(401).json({ message: "Invalid credentials" });

    // verify password (adapt field name if needed)
    const passwordHash = userDoc.passwordHash ?? userDoc.password;
    const passwordMatches = await bcrypt.compare(password, passwordHash);
    if (!passwordMatches) return res.status(401).json({ message: "Invalid credentials" });

    if (!userDoc.verified) {
      const hasOtp = !!userDoc.otp;
      const otpVerified = !!userDoc.otpVerified;

      let otpExpired = true;
      if (userDoc.otpExpires) {
        otpExpired = Date.now() > new Date(userDoc.otpExpires).getTime();
      } else if (userDoc.otpCreatedAt) {
        otpExpired = Date.now() - new Date(userDoc.otpCreatedAt).getTime() > ONE_HOUR_MS;
      } else {
        otpExpired = true; // conservative fallback
      }
      if (hasOtp && !otpVerified) {
        if (otpExpired) {
          // setUserOtp expected to save hashed OTP in DB and return plaintext OTP
          const newPlainOtp = await setUserOtp(userDoc);
          try {
            await sendOtpEmail(userDoc.email, newPlainOtp);
          } catch (mailErr) {
            console.error("Failed to send OTP email:", mailErr);
            // continue — still redirect user to verify so they can request/resend as needed
          }
        }

        const verificationToken = generateVerificationToken({
          uid: userDoc._id.toString(),
          email: userDoc.email,
        });

        res.cookie("verificationToken", verificationToken, cookieOpts(60 * 60 * 1000)); // 1 hour
        return res.status(200).json({redirectTo:"/verify",message:"Redirecting..."})
      }

      // No OTP present -> create one, send, redirect
      const newPlainOtp = await setUserOtp(userDoc);
      try {
        await sendOtpEmail(userDoc.email, newPlainOtp);
      } catch (mailErr) {
        console.error("Failed to send OTP email:", mailErr);
      }

      const verificationToken = generateVerificationToken({
        uid: userDoc._id.toString(),
        email: userDoc.email,
      });

      res.cookie("verificationToken", verificationToken, cookieOpts(60 * 60 * 1000)); // 1 hour
      return res.status(200).json({redirectTo:"/verify",message:"Redirecting..."})
    }

    // User is verified -> issue session token and return success
    const sessionToken = generateVerificationToken({
      uid: userDoc._id.toString(),
      email: userDoc.email,
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

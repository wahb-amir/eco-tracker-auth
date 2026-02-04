// routes/register.js
import express from "express";
import User from "../../model/User.js";
import {
  setUserOtp,
  generateVerificationToken,
} from "../../utils/token.js";
import { sendOtpEmail } from "../../utils/mailer.js";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    let { email, password, name } = req.body;
    // ---------- validation ----------
    if (!email || !password || !name) {
      return res.status(400).json({ msg: "All fields are required" });
    }

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof name !== "string"
    ) {
      return res.status(400).json({ msg: "Credentials must be strings" });
    }

    email = email.trim().toLowerCase();
    name = name.trim();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ msg: "Invalid email address" });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ msg: "Password must be at least 8 characters" });
    }

    // ---------- check existing ----------
    const existing = await User.findOne({ email });
    if (existing) {
      return res
        .status(409)
        .json({ msg: "User with this email already exists" });
    }

    // ---------- create user ----------
    const userDoc = new User({ name, email, password });
    await userDoc.save();

    // ---------- generate OTP ----------
    const otp = await setUserOtp(userDoc); // hashed in DB

    // ---------- generate verification cookie ----------
    const verificationToken = generateVerificationToken({
      uid: userDoc._id.toString(),
      email: userDoc.email,
    });

    res.cookie("verificationToken", verificationToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
      path: "/",
    });

    // ---------- send OTP email ----------
    try {
      await sendOtpEmail(email, otp, { expiryMinutes: 60 });
    } catch (mailErr) {
      // cleanup on failure
      try {
        await User.deleteOne({ _id: userDoc._id });
      } catch (cleanupErr) {
        console.error("Failed to cleanup user:", cleanupErr);
      }

      console.error("Error sending OTP email:", mailErr);
      return res.status(500).json({ msg: "Failed to send verification email" });
    }

    return res.status(201).json({
      msg: `Account created. Verification code sent to ${email}`,
    });
  } catch (e) {
    console.error("Error in register:", e);

    if (e?.code === 11000) {
      return res.status(409).json({ msg: "User with this email already exists" });
    }

    return res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router;
